// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "sync_session.hpp"
#include "sha256.hpp"
#include "native_filesystem.hpp"
#include <algorithm>
#include <limits>

namespace ck::files {
namespace {
template<class T> Observation<T> reject(const char* op, ObservationState s = ObservationState::Changed) {
    return Observation<T>::unavailable(s, {ErrorDomain::Adapter,
        static_cast<std::int64_t>(AdapterError::ProviderReviewRequired), op});
}
template<class T, class U> Observation<T> propagate(const Observation<U>& o) {
    return Observation<T>::unavailable(o.state(), o.unavailable_detail()->error);
}
SyncDigest hash(std::span<const std::byte> b) { Sha256 h; h.update(b); return h.digest(); }
void append(std::vector<std::byte>& b, const SyncDigest& d) { b.insert(b.end(), d.begin(), d.end()); }
void put(std::vector<std::byte>& b, std::uint64_t v) {
    for (unsigned i=0; i<8; ++i) b.push_back(std::byte((v >> (8*i)) & 255));
}
std::uint64_t get(std::span<const std::byte> b, std::size_t at) {
    std::uint64_t n=0;
    for (unsigned i=0; i<8; ++i) n |= std::uint64_t(std::to_integer<unsigned>(b[at+i])) << (i*8);
    return n;
}
SyncDigest digest_at(std::span<const std::byte> b, std::size_t at) {
    SyncDigest d; std::copy_n(b.begin()+at, 32, d.begin()); return d;
}
std::string hex(const SyncDigest& d) {
    std::string s; for(auto c:d) { const auto n=std::to_integer<unsigned>(c);
        s += "0123456789abcdef"[n>>4]; s += "0123456789abcdef"[n&15]; } return s;
}
constexpr std::uint64_t envelope_magic = 0x314e455347534b43ULL; // CKSGSEN1
constexpr std::uint64_t intent_magic = 0x31544e4947534b43ULL;
using Bytes = std::vector<std::byte>;
using MaybeBytes = std::optional<Bytes>;
struct Generation { std::uint64_t number; SyncBaseline baseline; SyncDigest digest; };
Bytes envelope(const SyncSessionIdentity& id, std::uint64_t gen, std::span<const std::byte> codec) {
    Bytes b; put(b,envelope_magic); put(b,gen); append(b,id.pair); put(b,codec.size());
    b.insert(b.end(),codec.begin(),codec.end()); append(b,hash(b)); return b;
}
std::optional<Generation> decode(const MaybeBytes& bytes, const SyncSessionIdentity& id, SyncBaselineLimits l) {
    if (!bytes || bytes->size()<88) return {};
    const auto& b=*bytes;
    if(get(b,0)!=envelope_magic || !get(b,8) || digest_at(b,16)!=id.pair ||
        get(b,48)!=b.size()-88 || digest_at(b,b.size()-32)!=hash(std::span(b).first(b.size()-32))) return {};
    auto codec=decode_sync_baseline(std::span(b).subspan(56,b.size()-88),l);
    if(!codec.value() || codec.value()->policy_fingerprint!=id.policy) return {};
    return Generation{get(b,8),std::move(codec).take_value(),hash(b)};
}
SyncDigest history_key(const SyncSessionIdentity& id) {
    Bytes b;put(b,0x3154534948534b43ULL);
    const bool ordered=id.left_root<id.right_root;
    append(b,ordered?id.left_root:id.right_root);append(b,ordered?id.right_root:id.left_root);return hash(b);
}
// V1 history is an initialized watermark. V2 pending history is written only
// before the first baseline intent; it cannot erase an initialized watermark.
Bytes history_record(const SyncSessionIdentity& id,bool initialized) {
    Bytes b;put(b,initialized?0x3154534948534b43ULL:0x3254534948534b43ULL);append(b,history_key(id));append(b,id.pair);append(b,id.policy);append(b,hash(b));return b;
}
// 0 corrupt, 1 initialized current binding, 2 another binding, 3 pending first initialization.
unsigned history_state(const MaybeBytes& bytes,const SyncSessionIdentity& id) {
    if(!bytes || bytes->size()!=136) return 0;const auto& b=*bytes;
    const auto magic=get(b,0);
    if((magic!=0x3154534948534b43ULL && magic!=0x3254534948534b43ULL) || digest_at(b,8)!=history_key(id) ||
        digest_at(b,104)!=hash(std::span(b).first(104))) return 0;
    if(digest_at(b,40)!=id.pair || digest_at(b,72)!=id.policy) return 2;
    return magic==0x3154534948534b43ULL?1:3;
}
Observation<bool> initialize_history(SyncSessionBackend& backend,const SyncSessionIdentity& id) {
    const auto name=hex(history_key(id));auto bytes=history_record(id,true);
    auto r=backend.stage(name+".intent-stage",bytes);if(!r.value()) return r;
    r=backend.publish(name+".intent-stage",name+".history");if(!r.value()) return r;
    return backend.flush_directory();
}
struct Intent { std::uint64_t old_gen; SyncDigest old_hash, new_hash; };
Bytes encode_intent(const SyncSessionIdentity& id, const Intent& in) {
    Bytes b; put(b,intent_magic); append(b,id.pair); put(b,in.old_gen);
    append(b,in.old_hash); append(b,in.new_hash); append(b,hash(b)); return b;
}
std::optional<Intent> decode_intent(const MaybeBytes& bytes, const SyncSessionIdentity& id) {
    if(!bytes || bytes->size()!=144) return {};
    const auto& b=*bytes;
    if(get(b,0)!=intent_magic || digest_at(b,8)!=id.pair ||
        digest_at(b,112)!=hash(std::span(b).first(112)) || get(b,40)==UINT64_MAX) return {};
    Intent in{get(b,40),digest_at(b,48),digest_at(b,80)};
    if(!in.old_gen && in.old_hash!=SyncDigest{}) return {};
    return in;
}
}
SyncSession::SyncSession(std::unique_ptr<SyncSessionBackend> b, SyncSessionIdentity id, SyncBaselineLimits l)
    : backend_(std::move(b)), identity_(id), limits_(l), prefix_(hex(id.pair)) {}
Observation<std::unique_ptr<SyncSession>> SyncSession::open(std::unique_ptr<SyncSessionBackend> b,
    const SyncDigest& policy, SyncBaselineLimits limits) {
    using R=Observation<std::unique_ptr<SyncSession>>;
    if(!b) return reject<std::unique_ptr<SyncSession>>("sync_session.backend",ObservationState::Failed);
    // Validate limits with the existing codec before deriving allocation bounds.
    auto valid=encode_sync_baseline(SyncBaseline{policy,{}},limits);
    if(!valid.value()) return propagate<std::unique_ptr<SyncSession>>(valid);
    SyncSessionIdentity id{b->left_identity(),b->right_identity(),{}, {}};
    Bytes binding; put(binding,0x31594c4f50534b43ULL); append(binding,id.left_root);
    append(binding,id.right_root); append(binding,policy); id.policy=hash(binding);
    put(binding,0x3152494150534b43ULL); id.pair=hash(binding);
    auto s=std::unique_ptr<SyncSession>(new SyncSession(std::move(b),id,limits));
    auto r=s->refresh(); if(!r.value()) return propagate<std::unique_ptr<SyncSession>>(r);
    return R::available(std::move(s));
}
Observation<bool> SyncSession::finish_io() {
    finished_=true; // Even a throwing result construction revokes all I/O authority.
    return backend_->finish_io();
}
Observation<bool> SyncSession::revalidate() {
    if(finished_)return reject<bool>("sync_session.finished");
    return backend_->revalidate();
}
Observation<bool> SyncSession::refresh() {
    if(finished_)return reject<bool>("sync_session.finished");
    uncertain_=true;
    auto valid=backend_->revalidate(); if(!valid.value()) return valid;
    auto read=[&](const char* suffix) { return backend_->read(prefix_+suffix,limits_.max_wire_bytes+88); };
    auto c=read(".baseline"); if(!c.value()) return propagate<bool>(c);
    auto p=read(".previous"); if(!p.value()) return propagate<bool>(p);
    auto i=read(".intent"); if(!i.value()) return propagate<bool>(i);
    auto n=read(".next"); if(!n.value()) return propagate<bool>(n);
    auto history=backend_->read(hex(history_key(identity_))+".history",136);
    if(!history.value()) return propagate<bool>(history);
    const auto binding=history_state(*history.value(),identity_);
    if(*history.value() && binding!=1 && binding!=3) {
        snapshot_={};snapshot_.state=binding==2?SyncSessionState::HistoryChanged:SyncSessionState::ReviewRequired;
        loaded_digest_={};uncertain_=false;return Observation<bool>::available(true);
    }
    if(!*history.value() && (*c.value() || *p.value() || *i.value())) {
        snapshot_={};loaded_digest_={};uncertain_=false;return Observation<bool>::available(true);
    }
    auto current=decode(*c.value(),identity_,limits_), previous=decode(*p.value(),identity_,limits_);
    auto next=decode(*n.value(),identity_,limits_);
    SyncSessionSnapshot out;
    if(previous) out.previous=previous->baseline;
    auto review=[&]() { snapshot_=std::move(out); loaded_digest_={}; uncertain_=false;
        return Observation<bool>::available(true); };
    bool recovered=false;
    if(*i.value()) {
        const auto intent=decode_intent(*i.value(),identity_);
        if(!intent) return review();
        const auto& in=*intent;
        const bool old_current=current && current->number==in.old_gen && current->digest==in.old_hash;
        const bool old_previous=previous && previous->number==in.old_gen && previous->digest==in.old_hash;
        const bool new_current=current && current->number==in.old_gen+1 && current->digest==in.new_hash;
        const bool new_next=next && next->number==in.old_gen+1 && next->digest==in.new_hash;
        const bool empty_old=!in.old_gen && !*c.value() && !*p.value();
        if(new_current && (old_previous || (!in.old_gen && !*p.value()))) {
            // Publication happened; make its directory entry durable BEFORE
            // removing the durable intent. An orphan next is acceptable only
            // when it is byte-for-byte the intended new generation.
            if(*n.value() && !new_next) return review();
        } else if(new_next && (old_current || (!*c.value() && old_previous) || empty_old)) {
            if(old_current) {
                auto r=backend_->publish(prefix_+".baseline",prefix_+".previous"); if(!r.value()) return r;
                r=backend_->flush_directory(); if(!r.value()) return r;
            }
            auto r=backend_->publish(prefix_+".next",prefix_+".baseline"); if(!r.value()) return r;
            if(old_current) previous=std::move(current);
            current=std::move(next);
        } else return review();
        auto r=backend_->flush_directory(); if(!r.value()) return r;
        // Make initialized history durable BEFORE retiring the only durable
        // intent that distinguishes first-run recovery from lost baseline data.
        if(binding==3) { r=initialize_history(*backend_,identity_);if(!r.value()) return r; }
        r=backend_->remove(prefix_+".next"); if(!r.value()) return r;
        r=backend_->remove(prefix_+".intent"); if(!r.value()) return r;
        r=backend_->flush_directory(); if(!r.value()) return r;
        recovered=true;
    } else {
        if((binding==1 && !*c.value() && !*p.value()) || (binding==3 && (*c.value() || *p.value()))) return review();
        if((*c.value() && !current) || (*p.value() && !previous) || (!current && previous)) return review();
        if(current && ((current->number==1 && previous) ||
            (current->number>1 && (!previous || previous->number!=current->number-1)))) return review();
    }
    if(current) {
        out.state=recovered ? SyncSessionState::Recovered : SyncSessionState::Ready;
        out.generation=current->number; out.baseline=std::move(current->baseline); loaded_digest_=current->digest;
    } else { out.state=SyncSessionState::FirstRun; loaded_digest_={}; }
    out.previous=previous ? std::optional<SyncBaseline>(std::move(previous->baseline)) : std::nullopt;
    valid=backend_->revalidate(); if(!valid.value()) return valid;
    snapshot_=std::move(out); uncertain_=false; return Observation<bool>::available(true);
}
Observation<SyncBaselineAdvance> SyncSession::commit(std::uint64_t expected,
    std::span<const SyncBaselineUpdate> updates, bool approve_first_run, std::function<bool()> cancelled) {
    if(finished_)return reject<SyncBaselineAdvance>("sync_session.finished");
    if(uncertain_ || (snapshot_.state==SyncSessionState::ReviewRequired || snapshot_.state==SyncSessionState::HistoryChanged) ||
        expected!=snapshot_.generation || expected==UINT64_MAX ||
        (snapshot_.state==SyncSessionState::FirstRun && !approve_first_run))
        return reject<SyncBaselineAdvance>("sync_session.commit.precondition");
    auto cancellation=[&]() { return cancelled && cancelled(); };
    if(cancellation()) return reject<SyncBaselineAdvance>("sync_session.cancelled");
    const auto remembered=loaded_digest_;
    auto refreshed=refresh(); if(!refreshed.value()) return propagate<SyncBaselineAdvance>(refreshed);
    if((snapshot_.state==SyncSessionState::ReviewRequired || snapshot_.state==SyncSessionState::HistoryChanged) || snapshot_.generation!=expected || loaded_digest_!=remembered)
        return reject<SyncBaselineAdvance>("sync_session.commit.cas");
    auto advanced=advance_sync_baseline(snapshot_.baseline ? &*snapshot_.baseline : nullptr,
        updates,identity_.policy,limits_);
    if(!advanced.value()) return advanced;
    auto codec=encode_sync_baseline(advanced.value()->baseline,limits_);
    if(!codec.value()) return propagate<SyncBaselineAdvance>(codec);
    auto bytes=envelope(identity_,expected+1,*codec.value());
    auto intent=encode_intent(identity_,{expected,remembered,hash(bytes)});
    uncertain_=true; // Any later exception/failure requires recovery, even stage failure.
    auto step=[&](Observation<bool> r) -> std::optional<UnavailableObservation> {
        if(!r.value()) return *r.unavailable_detail(); return {};
    };
    auto failed=[&](const UnavailableObservation& d) {
        return Observation<SyncBaselineAdvance>::unavailable(d.state,d.error);
    };
    // Record the first policy binding before creating any generation. A
    // later policy or reversed root order encounters explicit history review.
    // The marker is never overwritten by a different policy automatically.
    if(!expected) {
        const auto name=hex(history_key(identity_));auto record=history_record(identity_,false);
        if(auto e=step(backend_->stage(name+".intent-stage",record))) return failed(*e);
        if(auto e=step(backend_->publish(name+".intent-stage",name+".history"))) return failed(*e);
        if(auto e=step(backend_->flush_directory())) return failed(*e);
    }
    // Durable new payload -> durable intent -> durable old generation ->
    // durable publication -> durable intent retirement. Recovery never infers
    // an intended commit merely from the existence of a staged payload.
    if(auto e=step(backend_->stage(prefix_+".next",bytes))) return failed(*e);
    if(auto e=step(backend_->flush_directory())) return failed(*e);
    if(cancellation()) return reject<SyncBaselineAdvance>("sync_session.cancelled");
    if(auto e=step(backend_->stage(prefix_+".intent-stage",intent))) return failed(*e);
    if(cancellation()) return reject<SyncBaselineAdvance>("sync_session.cancelled");
    if(auto e=step(backend_->publish(prefix_+".intent-stage",prefix_+".intent"))) return failed(*e);
    if(auto e=step(backend_->flush_directory())) return failed(*e);
    if(expected) {
        if(auto e=step(backend_->publish(prefix_+".baseline",prefix_+".previous"))) return failed(*e);
        if(auto e=step(backend_->flush_directory())) return failed(*e);
    }
    if(auto e=step(backend_->publish(prefix_+".next",prefix_+".baseline"))) return failed(*e);
    if(auto e=step(backend_->flush_directory())) return failed(*e);
    if(!expected) {
        if(auto e=step(initialize_history(*backend_,identity_))) return failed(*e);
    }
    if(auto e=step(backend_->remove(prefix_+".intent"))) return failed(*e);
    if(auto e=step(backend_->flush_directory())) return failed(*e);
    snapshot_.previous=std::move(snapshot_.baseline);
    snapshot_.baseline=advanced.value()->baseline;
    snapshot_.generation=expected+1; snapshot_.state=SyncSessionState::Ready;
    loaded_digest_=hash(bytes); uncertain_=false;
    return advanced;
}
Observation<PreparedJournalRoot::Pointer> acquire_native_sync_storage_root(const NativeAbsolutePath& address) {
    NativeFileSystem fs;
    auto directory=fs.open_native_directory(address);
    if(!directory.value())return propagate<PreparedJournalRoot::Pointer>(directory);
    PreparedJournalRootRequest request;
    request.parent=std::move(directory).take_value();
    request.navigation_hint=address;
    JournalRootPreparationProgress progress;
    return prepare_native_journal_root(std::move(request),progress);
}
} // namespace ck::files
