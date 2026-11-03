// SPDX-License-Identifier: LGPL-2.0-or-later
// Actual native leaf close + persistent allocation failure. No model owners.
#define CK_HIERARCHY_SESSION_LEASE_ENTRY existing_hierarchy_lease_cases
#include "native_sync_hierarchy_session_lease_tests.cpp"
#undef CK_HIERARCHY_SESSION_LEASE_ENTRY
#include <type_traits>
static_assert(!noexcept(std::declval<NativeHierarchyContext&>().finish_io()));
static_assert(!noexcept(std::declval<NativeHierarchyBinding&>().finish_io()));
static_assert(!noexcept(std::declval<const detail::SessionReaderFailure&>().result()));
static_assert(noexcept(std::declval<NativeHierarchyContext&>().drain()));
static_assert(noexcept(std::declval<const SyncSession&>().reader_failure()));
namespace {
void persistent_reader_close(bool at_commit){
 Fixture f;auto s=session(f);auto c=get(NativeHierarchyContext::borrow(*s));auto b=get(c->bind(false,path({"d","e","file"})));struct stat st{};CHECK(lstat((f.root/"left/d/e/file").c_str(),&st)==0);
 fault::dev=st.st_dev;fault::ino=st.st_ino;fault::hits=0;fault::persistent_oom=true;fault::oom_after_close=true;fault::armed=true;
 bool caught=false;NativeHierarchyFailure helper{};detail::SessionReaderFailure reader{};
 try{if(at_commit)(void)s->commit(s->snapshot().generation,{},true);else (void)s->finish_io();}
 catch(const std::bad_alloc&){
   // ONLY POD capture + drain while OOM remains armed. No error formatter,
   // empty std::string, Observation default construction or fallback result.
   helper=c->drain();reader=s->reader_failure();
   if(s->root_handle(false)!=-1)try{(void)s->finish_io();}catch(...){ }
   caught=true;
 }
 const bool still_armed=fault::fail_alloc;
 fault::fail_alloc=fault::persistent_oom=false;
 CHECK(caught&&still_armed&&helper.present&&reader.failed);
 CHECK(helper.domain==ErrorDomain::Posix&&helper.code==EIO&&reader.domain==ErrorDomain::Posix&&reader.code==EIO&&fault::hits==1);
 CHECK(s->root_handle(false)==-1&&s->root_handle(true)==-1);
 auto repeated=s->finish_io();CHECK(!repeated.value()&&repeated.unavailable_detail()->error.code==EIO&&fault::hits==1);
}
}
int main(){try{CHECK(existing_hierarchy_lease_cases()==0);persistent_reader_close(false);persistent_reader_close(true);std::printf("PERSISTENT_OOM_NATIVE_READER checks=%u PASS\n",checks);return 0;}catch(const std::exception& e){fault::armed=fault::fail_alloc=fault::persistent_oom=false;std::fprintf(stderr,"FAIL %s\n",e.what());return 1;}}
