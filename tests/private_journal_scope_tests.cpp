// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "private_journal_scope.hpp"
#include "native_filesystem.hpp"
#include "platform/private_journal_scope_native.hpp"
#include <cassert>
#include <cstdio>
#include <cstring>
#include <string>

using namespace ck::files;
namespace {
template<class T> T take(Observation<T> result) {
    if(!result.value()) {
        const auto& e=*result.unavailable_detail();
        std::fprintf(stderr,"private scope: %s state=%d domain=%d code=%lld\n",
            e.error.operation.c_str(),int(e.state),int(e.error.domain),static_cast<long long>(e.error.code));
        std::abort();
    }
    return std::move(result).take_value();
}
NativeName name(const char* text) {
#ifdef _WIN32
    std::u16string units;for(;*text;++text)units.push_back(static_cast<char16_t>(*text));
    return *NativeName::from_windows(std::move(units));
#else
    return *NativeName::from_posix(text);
#endif
}
std::shared_ptr<const DirectoryCursor> child(const std::shared_ptr<const DirectoryCursor>& parent,const char* text) {
    return std::shared_ptr<const DirectoryCursor>(take(parent->create_child_directory(name(text))));
}
void overlap(Observation<JournalScopeGuard::Pointer> result) {
    assert(!result.value()&&result.state()==ObservationState::Unsupported);
    const auto& error=result.unavailable_detail()->error;
    assert(error.domain==ErrorDomain::Adapter&&error.code==static_cast<std::int64_t>(AdapterError::PlanTopologyUnsafe));
}
class FakeCursor final:public DirectoryCursor {
public:
    mutable unsigned calls=0;
    explicit FakeCursor(ObjectIdentity id):DirectoryCursor(Observation<ObjectIdentity>::available(std::move(id))){}
    Observation<BasicMetadata> inspect_basic() const override {++calls;return Observation<BasicMetadata>::unavailable(ObservationState::Unknown);}
protected:
    Observation<DirectoryStep> next_step() override {++calls;return Observation<DirectoryStep>::available(DirectoryEnd{});}
};
class FakeRoot final:public PreparedJournalRoot {
public:
    mutable unsigned calls=0;
    ObjectIdentity id;
    std::optional<NativeAbsolutePath> hint;
    Observation<std::unique_ptr<OperationJournalFile>> open_journal(const NativeName&,bool) override {++calls;return Observation<std::unique_ptr<OperationJournalFile>>::unavailable(ObservationState::Unknown);}
    Observation<bool> revalidate() const override {++calls;return Observation<bool>::available(true);}
    Observation<bool> sync() override {++calls;return Observation<bool>::available(true);}
    Observation<bool> finish_io() override {++calls;return Observation<bool>::available(true);}
    const ObjectIdentity& identity() const noexcept override {++calls;return id;}
    NameEncoding encoding() const noexcept override {++calls;return NameEncoding::PosixBytes;}
    const std::optional<NativeAbsolutePath>& navigation_address() const noexcept override {++calls;return hint;}
};
int run(NativeAbsolutePath scratch) {
    NativeFileSystem first,second;
    auto parent=std::shared_ptr<const DirectoryCursor>(take(first.open_native_directory(scratch)));
    auto source=child(parent,"source");
    auto destination=child(parent,"destination");
    PreparedJournalRootRequest request;
    request.parent=parent;request.child=name("journals");request.disposition=JournalRootDisposition::ProvisionChild;
    // A deliberately wrong hint is not scope evidence or reopening authority.
    request.navigation_hint=take(scratch.child_address(name("source")));
    JournalRootPreparationProgress progress;
    auto root=take(prepare_native_journal_root(std::move(request),progress));
    assert(progress.directory_creates==1);
    auto source_guard=take(JournalScopeGuard::create(root,source));
    auto destination_guard=take(JournalScopeGuard::create(root,destination));
    {
        auto topology=take(detail::open_scope_directory_cursor(root,source));
        auto cursor_parent=take(source->open_parent_directory());
        for(unsigned depth=0;depth<2;++depth) {
            const auto basic=depth?take(cursor_parent->inspect_basic()):take(source->inspect_basic());
            const auto compact=take(topology->inspect());
            assert(compare_identity(compact.identity,*basic.identity.value())==IdentityComparison::Same);
            assert(compact.mount_id==*basic.mount_id.value()&&compact.link_count==*basic.link_count.value());
            assert(compact.modified==*basic.modified.value()&&compact.changed==*basic.changed.value());
            if(!depth)topology=take(topology->open_parent());
        }
    }
    assert(take(source_guard->check_root())&&take(destination_guard->check_root()));
    assert(take(JournalScopeGuard::check_pair(source_guard,destination_guard)));
    auto invalid_pair=JournalScopeGuard::check_pair(source_guard,{});
    assert(!invalid_pair.value()&&invalid_pair.state()==ObservationState::Failed&&
        invalid_pair.unavailable_detail()->error.code==static_cast<std::int64_t>(AdapterError::InvalidIdentifier));
    overlap(JournalScopeGuard::create(root,parent));
    auto state=std::shared_ptr<const DirectoryCursor>(take(parent->open_directory_child(name("journals"))));
    overlap(JournalScopeGuard::create(root,state));
    auto nested=child(state,"nested");
    overlap(JournalScopeGuard::create(root,nested));
    auto state_entry=take(HeldChild::observe(parent,name("journals")));
    auto denied=source_guard->check_entry(*state_entry);
    assert(!denied.value()&&denied.state()==ObservationState::Unsupported&&
        denied.unavailable_detail()->error.code==static_cast<std::int64_t>(AdapterError::PlanTopologyUnsafe));
    // The same basename outside the actual native Root is ordinary input.
    auto shadow=child(source,"journals");
    auto shadow_entry=take(HeldChild::observe(source,name("journals")));
    assert(take(source_guard->check_entry(*shadow_entry)));
    auto shadow_guard=take(JournalScopeGuard::create(root,shadow));
    assert(take(shadow_guard->check_root()));
    // Different adapter instances are proved through native providers, not by
    // equating their deliberately distinct AdapterScope tokens.
    auto source_address=take(scratch.child_address(name("source")));
    auto other_source=std::shared_ptr<const DirectoryCursor>(take(second.open_native_directory(source_address)));
    assert(compare_identity(*source->identity().value(),*other_source->identity().value())==IdentityComparison::Unknown);
    auto other_guard=take(JournalScopeGuard::create(root,other_source));
    assert(take(JournalScopeGuard::check_pair(other_guard,destination_guard)));
    auto other_parent=std::shared_ptr<const DirectoryCursor>(take(second.open_native_directory(scratch)));
    overlap(JournalScopeGuard::create(root,other_parent));
    // File actions act on the selected file, not the whole parent subtree.
    auto writer=take(parent->create_child_file(name("ordinary")));
    assert(take(writer->finish_content_writes()));writer.reset();
    auto ordinary=take(HeldChild::observe(parent,name("ordinary")));
    auto file_guard=take(JournalScopeGuard::create_for_entry(root,*ordinary));
    assert(take(file_guard->check_entry(*ordinary)));
    overlap(JournalScopeGuard::create_for_entry(root,*state_entry));
    writer=take(state->create_child_file(name("private-state")));
    assert(take(writer->finish_content_writes()));writer.reset();
    auto private_file=take(HeldChild::observe(state,name("private-state")));
    overlap(JournalScopeGuard::create_for_entry(root,*private_file));
    assert(take(parent->create_hard_link(name("ordinary"),*ordinary->metadata().identity.value(),
        *source,name("ordinary-alias"))));
    auto ordinary_alias=take(HeldChild::observe(source,name("ordinary-alias")));
    assert(*ordinary_alias->metadata().link_count.value()>1);
    assert(take(source_guard->check_entry(*ordinary_alias)));
    auto ordinary_alias_guard=take(JournalScopeGuard::create_for_entry(root,*ordinary_alias));
    assert(take(ordinary_alias_guard->check_entry(*ordinary_alias)));
    assert(take(state->create_hard_link(name("private-state"),*private_file->metadata().identity.value(),
        *source,name("private-alias"))));
    auto private_alias=take(HeldChild::observe(source,name("private-alias")));
    assert(*private_alias->metadata().link_count.value()>1);
    auto aliased=source_guard->check_entry(*private_alias);
    assert(!aliased.value()&&aliased.state()==ObservationState::Unsupported&&
        aliased.unavailable_detail()->error.domain==ErrorDomain::Adapter&&
        aliased.unavailable_detail()->error.code==static_cast<std::int64_t>(AdapterError::PlanTopologyUnsafe));
    overlap(JournalScopeGuard::create_for_entry(root,*private_alias));
    auto fake=std::make_shared<FakeCursor>(*source->identity().value());
    assert(!JournalScopeGuard::create(root,fake).value()&&fake->calls==0);
    assert(!detail::open_scope_directory_cursor(root,fake).value()&&fake->calls==0);
    auto fake_root=std::make_shared<FakeRoot>();
    assert(!JournalScopeGuard::create(fake_root,source).value()&&fake_root->calls==0);
    std::stop_source stop;stop.request_stop();
    auto cancelled=JournalScopeGuard::create(root,source,stop.get_token());
    assert(!cancelled.value()&&cancelled.state()==ObservationState::Changed&&
        cancelled.unavailable_detail()->error.code==static_cast<std::int64_t>(AdapterError::InterruptedRead));
    source_guard.reset();destination_guard.reset();shadow_guard.reset();other_guard.reset();file_guard.reset();ordinary_alias_guard.reset();
    assert(take(root->finish_io()));root.reset();
    // Initial legacy address adoption obtains its own typed owner. It does not
    // reinterpret the bogus navigation hint that was attached to the old Root.
    auto journal_address=take(scratch.child_address(name("journals")));
    root=take(acquire_native_journal_root(journal_address));
    overlap(JournalScopeGuard::create(root,parent));
    assert(take(root->finish_io()));
    std::puts("journal scope: native topology, cross-engine identities, same-name input and forged-provider refusal passed");
    return 0;
}
}
#ifdef _WIN32
int wmain(int argc,wchar_t** argv) {
    assert(argc==2);std::u16string units;
    for(const auto* p=argv[1];*p;++p)units.push_back(static_cast<char16_t>(*p));
    return run(take(NativeAbsolutePath::from_windows(std::move(units))));
}
#else
int main(int argc,char** argv) {assert(argc==2);return run(take(NativeAbsolutePath::from_posix(argv[1])));}
#endif
