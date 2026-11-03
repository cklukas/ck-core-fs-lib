// SPDX-License-Identifier: LGPL-2.0-or-later
#include "native_sync_hierarchy_binding.hpp"
#include "native_filesystem.hpp"
#include "private_journal_scope.hpp"
#include "metadata_capture_job.hpp"
#include "platform/prepared_journal_root_bridge.hpp"
#include "child_lookup.hpp"
#include "platform/native_sync_session_lease.hpp"
#include <algorithm>
#include <array>
#include <atomic>
#include <cstring>
#include <limits>
#include <exception>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <sys/stat.h>
#endif
namespace ck::files {
namespace {
using Cursor=std::shared_ptr<const DirectoryCursor>;
constexpr std::size_t provider_fds=16384;
NativeHierarchyFailure scalar(ObservationState state,ErrorDomain domain,std::int64_t code,std::string_view tag)noexcept {
    NativeHierarchyFailure out;out.present=true;out.state=state;out.domain=domain;out.code=code;
    std::copy_n(tag.begin(),std::min(tag.size(),out.operation.size()-1),out.operation.begin());return out;
}
struct Failure {NativeHierarchyFailure error;};
[[noreturn]]void fail(const char* op,ObservationState state=ObservationState::Changed,AdapterError code=AdapterError::PlanDecisionStale){throw Failure{scalar(state,ErrorDomain::Adapter,static_cast<std::int64_t>(code),op)};}
template<class T>T take(Observation<T> o){if(auto e=o.unavailable_detail())throw Failure{scalar(e->state,e->error.domain,e->error.code,e->error.operation)};return std::move(o).take_value();}
void yes(Observation<bool> o){if(!take(std::move(o)))fail("hierarchy.native_false",ObservationState::Unknown,AdapterError::InvalidNativeResult);}
template<class T>bool eq(const Observation<T>& a,const Observation<T>& b){return a.value()&&b.value()?*a.value()==*b.value():a.state()==b.state();}
bool same_id(const BasicMetadata& a,const BasicMetadata& b){return a.identity.value()&&b.identity.value()&&compare_identity(*a.identity.value(),*b.identity.value())==IdentityComparison::Same;}
bool version(const BasicMetadata& a,const BasicMetadata& b){return same_id(a,b)&&eq(a.kind,b.kind)&&eq(a.mount_id,b.mount_id)&&eq(a.logical_size,b.logical_size)&&eq(a.link_count,b.link_count)&&eq(a.modified,b.modified)&&eq(a.changed,b.changed)&&eq(a.created,b.created)&&eq(a.posix_uid,b.posix_uid)&&eq(a.posix_gid,b.posix_gid)&&eq(a.posix_permissions,b.posix_permissions)&&eq(a.bsd_flags,b.bsd_flags)&&eq(a.windows_attributes,b.windows_attributes);}
void qualified(const BasicMetadata& b){if(!b.identity.value()||!b.kind.value()||!b.mount_id.value()||!b.link_count.value()||!b.modified.value()||!b.changed.value())fail("hierarchy.incomplete_native_metadata",ObservationState::Unsupported,AdapterError::UnqualifiedIdentity);}
std::size_t bytes(const NativeName& n){if(!n.is_valid())fail("hierarchy.invalid_name",ObservationState::Failed,AdapterError::InvalidIdentifier);if(auto p=n.posix_bytes())return p->size();if(auto p=n.windows_units())return p->size()*2;fail("hierarchy.foreign_name",ObservationState::Unsupported,AdapterError::UnrepresentableName);}

}
namespace detail {
struct HierarchyContextState final:MetadataCaptureFailureLatch,SessionReadConsumer {
    PreparedJournalRoot::Pointer root;
    NativeFileSystem fs;
    std::unique_ptr<SyncSessionBackend> backend;
    std::shared_ptr<NativeSessionLease> borrowed;
    std::array<Cursor,2> roots;
    std::array<JournalScopeGuard::Pointer,2> guards;
    std::array<std::optional<BasicMetadata>,2> initial;
    std::vector<std::weak_ptr<HierarchyBindingState>> bindings{std::initializer_list<std::weak_ptr<HierarchyBindingState>>{}};
    NativeHierarchyLimits limits;NativeHierarchyUsage used;
    std::chrono::steady_clock::time_point started=std::chrono::steady_clock::now();
    std::uint64_t epoch=0;bool finished=false;
    mutable bool failed=false;mutable PreparedJournalConsumerFailure error;
    void record(ObservationState state,ErrorDomain domain,std::int64_t code,std::string_view tag)const noexcept {
        if(root)record_prepared_journal_consumer_failure(*root,state,domain,code,tag);
        if(!failed){failed=true;error.state=state;error.domain=domain;error.code=code;const auto n=std::min(tag.size(),error.operation.size()-1);std::copy_n(tag.begin(),n,error.operation.begin());}
    }
    void record_first(MetadataCaptureCleanupError e)const noexcept override{record(e.state,e.domain,e.code,e.operation);}
    NativeHierarchyFailure first_failure()const noexcept {
        PreparedJournalConsumerFailure first;
        if(root&&read_prepared_journal_consumer_failure(*root,first))return scalar(first.state,first.domain,first.code,first.operation.data());
        if(failed)return scalar(error.state,error.domain,error.code,error.operation.data());
        return {};
    }
    Observation<bool> result()const {
        const auto first=first_failure();
        if(!first.present)return Observation<bool>::available(true);
        // No catch/reallocation fallback. finish_io callers have already drained;
        // other entry points drain during exception unwinding before propagation.
        return Observation<bool>::unavailable(first.state,{first.domain,first.code,first.operation.data()});
    }
    void check(std::stop_token stop){if(const auto first=first_failure();first.present)throw Failure{first};if(finished)fail("hierarchy.epoch_closed");if(stop.stop_requested())fail("hierarchy.cancelled",ObservationState::Unknown,AdapterError::InterruptedRead);if(std::chrono::steady_clock::now()-started>limits.max_elapsed)fail("hierarchy.elapsed_limit",ObservationState::Unknown,AdapterError::InventoryLimit);}
    void charge(std::size_t& count,std::size_t n,std::size_t max){if(count>max||n>max-count)fail("hierarchy.cumulative_limit",ObservationState::Unknown,AdapterError::InventoryLimit);count+=n;}
    void read(std::stop_token stop,std::size_t fds=0){check(stop);charge(used.reads,1,limits.max_reads);charge(used.fd_opens,fds,limits.max_fd_opens);}
    void session(std::stop_token stop){read(stop,provider_fds);yes(borrowed?borrowed->revalidate():backend->revalidate());check(stop);read(stop,provider_fds);yes(JournalScopeGuard::check_pair(guards[0],guards[1],stop));check(stop);}
    void compare_root(unsigned side,const BasicMetadata& b){qualified(b);if(*b.kind.value()!=ObjectKind::Directory||!same_id(*initial[side],b)||!eq(initial[side]->mount_id,b.mount_id))fail("hierarchy.root_changed");}
    void drain()noexcept;
    std::intptr_t raw_root(bool right){return borrowed?take(borrowed->handle(right)):backend->root_handle(right);}
    SessionReaderFailure revoke_readers()noexcept override {
        drain();SessionReaderFailure out;
        PreparedJournalConsumerFailure first;
        if(root&&read_prepared_journal_consumer_failure(*root,first)){out.failed=true;out.state=first.state;out.domain=first.domain;out.code=first.code;out.operation=first.operation;}
        else if(failed){out.failed=true;out.state=error.state;out.domain=error.domain;out.code=error.code;out.operation=error.operation;}
        return out;
    }
    ~HierarchyContextState(){drain();}
};
struct HierarchyBindingState final {
    struct Edge {Cursor parent;HeldChild::Pointer child;BasicMetadata parent_before;Cursor directory;};
    std::shared_ptr<HierarchyContextState> context;std::uint64_t epoch=0;
    unsigned side=0;std::vector<NativeName> names{std::initializer_list<NativeName>{}};std::vector<Edge> edges{std::initializer_list<Edge>{}};
    std::optional<BasicMetadata> root_before;
    NativeHierarchyPresence presence=NativeHierarchyPresence::Present;
    std::size_t missing=0,reservation=0;bool finished=false;
    Cursor missing_parent;std::optional<BasicMetadata> missing_parent_before;std::optional<NativeError> witness;
    void drain()noexcept{
        if(finished){return;}finished=true;MetadataCaptureCleanupScope scope(context.get());
        // Reverse child/parent ownership release, with Root latch installed.
        missing_parent.reset();for(auto it=edges.rbegin();it!=edges.rend();++it){it->directory.reset();it->child.reset();it->parent.reset();}edges.clear();
        context->used.retained_fds-=reservation;reservation=0;
    }
    ~HierarchyBindingState(){drain();}
};
void HierarchyContextState::drain()noexcept {
    if(finished){return;}finished=true;MetadataCaptureCleanupScope scope(this);
    for(auto& weak:bindings){if(auto binding=weak.lock())binding->drain();}bindings.clear();
    guards={};roots={};
    if(backend){try{auto o=backend->finish_io();if(auto e=o.unavailable_detail())record(e->state,e->error.domain,e->error.code,e->error.operation);else if(!*o.value())record(ObservationState::Unknown,ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"hierarchy.backend_close_false");}catch(...){if(!first_failure().present)record(ObservationState::Unknown,ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidNativeResult),"hierarchy.backend_close_exception");}backend.reset();}
    borrowed.reset();used.retained_fds=0;
}
}
namespace {
// Only references/POD are held by this scope. It never formats an exception.
struct DrainOnException final {
    const std::shared_ptr<detail::HierarchyContextState>& state;
    const int entered=std::uncaught_exceptions();
    ~DrainOnException()noexcept{if(std::uncaught_exceptions()>entered&&state)state->drain();}
};
template<class T>Observation<T> failure_result(const std::shared_ptr<detail::HierarchyContextState>& s,const NativeHierarchyFailure& fallback) {
    const auto first=s?s->first_failure():NativeHierarchyFailure{};
    const auto& chosen=first.present?first:fallback;
    return Observation<T>::unavailable(chosen.state,{chosen.domain,chosen.code,chosen.operation.data()});
}
void match_held_root(detail::HierarchyContextState& s,unsigned side){
    const auto& id=*s.initial[side]->identity.value();const auto raw=s.raw_root(side!=0);
#ifdef _WIN32
    FILE_ID_INFO info{};if(raw==-1||!GetFileInformationByHandleEx(reinterpret_cast<HANDLE>(raw),FileIdInfo,&info,sizeof(info)))fail("hierarchy.session_root_query",ObservationState::Unsupported,AdapterError::UnqualifiedIdentity);
    NativeIdentifier object;std::memcpy(object.bytes.data(),info.FileId.Identifier,16);
    if(id.scheme!=IdentityScheme::WindowsFileId128||id.volume!=NativeIdentifier::from_u64(info.VolumeSerialNumber)||id.object!=object)fail("hierarchy.session_root_mismatch");
#else
    struct stat info{};if(raw<0||fstat(static_cast<int>(raw),&info))fail("hierarchy.session_root_query",ObservationState::Unsupported,AdapterError::UnqualifiedIdentity);
    if(!S_ISDIR(info.st_mode)||id.scheme!=IdentityScheme::PosixDeviceInode||id.volume!=NativeIdentifier::from_u64(info.st_dev)||id.object!=NativeIdentifier::from_u64(info.st_ino))fail("hierarchy.session_root_mismatch");
#endif
}
void missing(detail::HierarchyContextState& s,const Cursor& parent,const NativeName& name,std::stop_token stop,std::optional<NativeError>* out=nullptr){
    for(unsigned pass=0;pass<2;++pass){s.read(stop,1);auto lookup=take(parent->lookup_child(name,ChildLookupMode::NativeDefault));const auto* c=lookup.context();const auto* w=lookup.missing_witness();
        if(lookup.state()!=ChildLookupState::Missing||!w||!c||c->mode!=ChildLookupMode::NativeDefault||c->requested!=name||!c->directory.value()||!parent->identity().value()||compare_identity(*c->directory.value(),*parent->identity().value())!=IdentityComparison::Same)fail("hierarchy.absence_not_native_missing");
#ifdef _WIN32
        constexpr auto family=detail::ChildLookupFamily::WindowsNt;
#else
        constexpr auto family=detail::ChildLookupFamily::PosixAt;
#endif
        if(!detail::definite_child_absence({ObservationState::Gone,*w},family))fail("hierarchy.absence_witness",ObservationState::Unsupported,AdapterError::UnqualifiedIdentity);
        if(out){*out=*w;}s.check(stop);
    }
}
void validate(detail::HierarchyBindingState& b,std::stop_token stop){
    auto& s=*b.context;s.check(stop);if(b.finished||b.epoch!=s.epoch)fail("hierarchy.binding_epoch");s.session(stop);
    if(b.presence==NativeHierarchyPresence::Missing){s.read(stop);auto before=take(b.missing_parent->inspect_basic());if(!version(before,*b.missing_parent_before))fail("hierarchy.absence_parent_changed");missing(s,b.missing_parent,b.names[b.missing],stop);s.read(stop);if(!version(before,take(b.missing_parent->inspect_basic())))fail("hierarchy.absence_parent_changed");}
    for(auto it=b.edges.rbegin();it!=b.edges.rend();++it){s.read(stop,1);s.charge(s.used.entries,1,s.limits.max_entries);auto refreshed=take(it->child->refresh(stop));if(!refreshed->continues(*it->child)||!version(it->child->metadata(),refreshed->metadata()))fail("hierarchy.member_changed");s.read(stop,provider_fds);yes(s.guards[b.side]->check_entry(*refreshed,stop));if(it->directory){s.read(stop);if(!version(it->child->metadata(),take(it->directory->inspect_basic())))fail("hierarchy.directory_changed");}s.read(stop);if(!version(it->parent_before,take(it->parent->inspect_basic())))fail("hierarchy.parent_changed");s.check(stop);}
    s.read(stop);if(!version(*b.root_before,take(s.roots[b.side]->inspect_basic())))fail("hierarchy.root_version_changed");s.session(stop);
}
}
NativeHierarchyContext::NativeHierarchyContext(std::shared_ptr<detail::HierarchyContextState> s)noexcept:state_(std::move(s)){}
NativeHierarchyContext::~NativeHierarchyContext()=default;
Observation<NativeHierarchyContext::Pointer> NativeHierarchyContext::open(PreparedJournalRoot::Pointer root,NativeAbsolutePath left,NativeAbsolutePath right,NativeHierarchyLimits limits,std::stop_token stop){
    std::shared_ptr<detail::HierarchyContextState> retained;
    DrainOnException on_exception{retained};
    try{
        if(!root||!limits.max_depth||limits.max_depth>1024||!limits.max_entries||!limits.max_wire_bytes||!limits.max_reads||limits.max_elapsed.count()<=0||limits.max_elapsed>std::chrono::hours(1)||limits.max_retained_fds<provider_fds+8||limits.max_fd_opens<provider_fds)fail("hierarchy.invalid_limits",ObservationState::Failed,AdapterError::InvalidLimit);
        auto s=std::make_shared<detail::HierarchyContextState>();retained=s;s->root=std::move(root);s->limits=limits;s->used.retained_fds=provider_fds+8;detail::MetadataCaptureCleanupScope scope(s.get());s->read(stop,provider_fds);
        s->backend=take(open_native_sync_session_backend(s->root,left,right));s->check(stop);
        for(unsigned side=0;side<2;++side){s->read(stop,2);s->roots[side]=Cursor(take(s->fs.open_native_directory(side?right:left)));s->read(stop);s->initial[side]=take(s->roots[side]->inspect_basic());qualified(*s->initial[side]);match_held_root(*s,side);s->read(stop,provider_fds);s->guards[side]=take(JournalScopeGuard::create(s->root,s->roots[side],stop));}
        static std::atomic<std::uint64_t> epochs{1};s->epoch=epochs.fetch_add(1);if(!s->epoch)fail("hierarchy.epoch_exhausted",ObservationState::Unsupported,AdapterError::InvalidIdentifier);s->session(stop);return Observation<Pointer>::available(Pointer(new NativeHierarchyContext(std::move(s))));
    }catch(const Failure& e){if(retained)retained->drain();return failure_result<Pointer>(retained,e.error);}catch(...){if(retained)retained->drain();throw;}
}
Observation<NativeHierarchyContext::Pointer> NativeHierarchyContext::borrow(SyncSession& session,NativeHierarchyLimits limits,std::stop_token stop){
    std::shared_ptr<detail::HierarchyContextState> retained;
    DrainOnException on_exception{retained};
    try{
        if(!limits.max_depth||limits.max_depth>1024||!limits.max_entries||!limits.max_wire_bytes||!limits.max_reads||limits.max_elapsed.count()<=0||limits.max_elapsed>std::chrono::hours(1)||limits.max_retained_fds<provider_fds+8||limits.max_fd_opens<provider_fds)fail("hierarchy.invalid_limits",ObservationState::Failed,AdapterError::InvalidLimit);
        auto s=std::make_shared<detail::HierarchyContextState>();retained=s;s->root=session.storage_root();s->limits=limits;s->used.retained_fds=provider_fds+8;
        detail::MetadataCaptureCleanupScope scope(s.get());s->read(stop,provider_fds);
        s->borrowed=take(detail::NativeSessionLease::borrow(session,s));s->root=s->borrowed->root_;s->epoch=s->borrowed->epoch_id();
        for(unsigned side=0;side<2;++side){s->read(stop,2);s->roots[side]=Cursor(take(s->borrowed->open_root(side!=0)));s->read(stop);s->initial[side]=take(s->roots[side]->inspect_basic());qualified(*s->initial[side]);match_held_root(*s,side);s->read(stop,provider_fds);s->guards[side]=take(JournalScopeGuard::create(s->root,s->roots[side],stop));}
        s->session(stop);return Observation<Pointer>::available(Pointer(new NativeHierarchyContext(std::move(s))));
    }catch(const Failure& e){if(retained)retained->drain();return failure_result<Pointer>(retained,e.error);}catch(...){if(retained)retained->drain();throw;}
}
Observation<NativeHierarchyBinding::Pointer> NativeHierarchyContext::bind(bool right,std::span<const NativeName> names,std::stop_token stop){
    DrainOnException on_exception{state_};
    try{auto s=state_;detail::MetadataCaptureCleanupScope scope(s.get());s->check(stop);if(names.empty()||names.size()>s->limits.max_depth)fail("hierarchy.depth_limit",ObservationState::Unknown,AdapterError::InventoryLimit);
        s->session(stop);for(const auto& name:names)s->charge(s->used.wire_bytes,bytes(name)+8,s->limits.max_wire_bytes);
        auto b=std::make_shared<detail::HierarchyBindingState>();b->context=s;b->side=right?1U:0U;b->epoch=s->epoch;
        const auto reserve=names.size()*3+8;s->charge(s->used.retained_fds,reserve,s->limits.max_retained_fds);b->reservation=reserve;b->names.assign(names.begin(),names.end());b->edges.reserve(names.size());
        auto parent=s->roots[b->side];s->read(stop);b->root_before=take(parent->inspect_basic());s->compare_root(b->side,*b->root_before);
        for(std::size_t index=0;index<names.size();++index){s->charge(s->used.entries,1,s->limits.max_entries);s->read(stop);auto before=take(parent->inspect_basic());qualified(before);s->read(stop,1);
            bool absent=false;{auto lookup=take(parent->lookup_child(names[index],ChildLookupMode::NativeDefault));absent=lookup.state()==ChildLookupState::Missing;if(!absent&&lookup.state()!=ChildLookupState::Found)fail("hierarchy.unknown_lookup",ObservationState::Unsupported,AdapterError::UnqualifiedIdentity);}
            if(absent){missing(*s,parent,names[index],stop,&b->witness);b->presence=NativeHierarchyPresence::Missing;b->missing=index;b->missing_parent=parent;b->missing_parent_before=before;break;}
            s->read(stop,1);auto held=take(HeldChild::observe(parent,names[index],stop));qualified(held->metadata());s->read(stop,provider_fds);yes(s->guards[b->side]->check_entry(*held,stop));const auto kind=*held->metadata().kind.value();if(kind!=ObjectKind::Directory&&kind!=ObjectKind::RegularFile)fail("hierarchy.no_follow_kind",ObservationState::Unsupported,AdapterError::FinalLinkRejected);
            if(!eq(held->metadata().mount_id,b->root_before->mount_id)||held->metadata().identity.value()->volume!=b->root_before->identity.value()->volume)fail("hierarchy.mount_crossing",ObservationState::Unsupported,AdapterError::PlanTopologyUnsafe);
            Cursor directory;if(index+1<names.size()){if(kind!=ObjectKind::Directory)fail("hierarchy.parent_not_directory",ObservationState::Unsupported,AdapterError::NotDirectory);s->read(stop,1);directory=Cursor(take(parent->open_directory_child(names[index])));s->read(stop);auto opened=take(directory->inspect_basic());if(!version(held->metadata(),opened))fail("hierarchy.directory_open_changed");for(const auto& edge:b->edges)if(same_id(edge.child->metadata(),opened))fail("hierarchy.directory_loop",ObservationState::Unsupported,AdapterError::PlanTopologyUnsafe);if(same_id(*b->root_before,opened))fail("hierarchy.directory_loop",ObservationState::Unsupported,AdapterError::PlanTopologyUnsafe);}
            b->edges.push_back({parent,std::move(held),before,directory});if(directory)parent=std::move(directory);s->check(stop);
        }
        validate(*b,stop);s->bindings.erase(std::remove_if(s->bindings.begin(),s->bindings.end(),[](const auto& p){return p.expired();}),s->bindings.end());s->bindings.push_back(b);return Observation<NativeHierarchyBinding::Pointer>::available(NativeHierarchyBinding::Pointer(new NativeHierarchyBinding(std::move(b))));
    }catch(const Failure& e){return failure_result<NativeHierarchyBinding::Pointer>(state_,e.error);}catch(...){state_->drain();throw;}
}
NativeHierarchyUsage NativeHierarchyContext::usage()const noexcept{return state_->used;}
Observation<bool> NativeHierarchyContext::finish_io(){state_->drain();return state_->result();}
NativeHierarchyBinding::NativeHierarchyBinding(std::shared_ptr<detail::HierarchyBindingState> s)noexcept:state_(std::move(s)){}
NativeHierarchyBinding::~NativeHierarchyBinding()=default;
NativeHierarchyPresence NativeHierarchyBinding::presence()const noexcept{return state_->presence;}
std::size_t NativeHierarchyBinding::missing_component()const noexcept{return state_->missing;}
std::uint64_t NativeHierarchyBinding::epoch()const noexcept{return state_->epoch;}
Observation<BasicMetadata> NativeHierarchyBinding::metadata()const{DrainOnException on_exception{state_->context};try{state_->context->check({});if(state_->finished)fail("hierarchy.binding_closed");if(state_->presence!=NativeHierarchyPresence::Present)fail("hierarchy.leaf_absent",ObservationState::Gone,AdapterError::NotApplicable);return Observation<BasicMetadata>::available(state_->edges.back().child->metadata());}catch(const Failure& e){return failure_result<BasicMetadata>(state_->context,e.error);}catch(...){state_->context->drain();throw;}}
Observation<bool> NativeHierarchyBinding::revalidate(std::stop_token stop){DrainOnException on_exception{state_->context};try{detail::MetadataCaptureCleanupScope scope(state_->context.get());validate(*state_,stop);return Observation<bool>::available(true);}catch(const Failure& e){return failure_result<bool>(state_->context,e.error);}catch(...){state_->context->drain();throw;}}
Observation<bool> NativeHierarchyBinding::finish_io(){DrainOnException on_exception{state_->context};state_->drain();return state_->context->result();}
NativeHierarchyFailure NativeHierarchyContext::drain()noexcept{state_->drain();return state_->first_failure();}
NativeHierarchyFailure NativeHierarchyBinding::drain()noexcept{state_->drain();return state_->context->first_failure();}
NativeHierarchyFailure NativeHierarchyContext::first_failure()const noexcept{return state_->first_failure();}
NativeHierarchyFailure NativeHierarchyBinding::first_failure()const noexcept{return state_->context->first_failure();}
} // namespace ck::files
