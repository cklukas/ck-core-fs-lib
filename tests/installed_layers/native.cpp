// SPDX-License-Identifier: LGPL-2.0-or-later
#include <native_filesystem.hpp>
#include <native_main_content_job.hpp>
#include <regular_metadata_preservation.hpp>
#include <cassert>
#include <cstdio>
#include <string_view>
using namespace ck::files;
namespace {
template<class T>T take(Observation<T> result){
    if(!result.value()){
        const auto& e=*result.unavailable_detail();
        std::fprintf(stderr,"installed native consumer: state=%u code=%lld op=%s\n",unsigned(e.state),
            static_cast<long long>(e.error.code),e.error.operation.c_str());std::abort();
    }
    return std::move(result).take_value();
}
}
int main(int argc,char**argv){
    assert(argc==2);
    const auto path=take(NativeAbsolutePath::from_host(std::filesystem::path(argv[1])));
    NativeFileSystem fs;auto directory=std::shared_ptr<const DirectoryCursor>(take(fs.open_native_directory(path)));
    const auto input=*NativeName::from_posix("input");
    auto held=take(HeldChild::observe_with_access(directory,input,EntryAccess::ContentRead));
#ifndef CK_LAYER_PLATFORM_ONLY
    auto main=take(NativeMainContentJob::begin_held(held,NativeMainContentLimits{{4},1024}));
    for(unsigned n=0;n<100&&main->progress().phase!=NativeMainContentPhase::DataReady;++n){
        const auto step=take(main->advance());assert(step.content_reads<=1&&step.content_bytes<=4);
    }
    assert(main->progress().phase==NativeMainContentPhase::DataReady);
    assert(take(main->finish_read()));assert(take(main->result())->main_bytes()==19);main.reset();
#endif
    MetadataReplayPolicy policy;policy.scope=RegularMetadataScope::OrdinaryCallerVisibleV1;
    policy.ownership=MetadataOwnership::CurrentCaller;
    auto preservation=take(RegularMetadataPreservation::create_with_policy(held,false,policy));
    assert(preservation->captured_metadata());held.reset();assert(take(preservation->finish_io()));preservation.reset();
#ifdef __linux__
    auto staging=take(directory->create_staging_file(*NativeName::from_posix("recovery-hint")));
    assert(staging.staging_namespace==StagingNamespace::Anonymous&&!staging.name);
    constexpr std::string_view bytes="published from installed Native";
    assert(take(staging.entry->write_content(0,{reinterpret_cast<const std::byte*>(bytes.data()),bytes.size()}))==bytes.size());
    assert(take(staging.entry->flush_content()));
    assert(take(staging.entry->publish_noreplace(*directory,*NativeName::from_posix("published"))));
    assert(take(staging.entry->finish_content_writes()));staging.entry.reset();
    auto read=take(directory->open_child(*NativeName::from_posix("published"),EntryAccess::ContentRead));
    const auto observed=take(read->read_content({1024}));assert(observed.complete);
    assert(std::string_view(reinterpret_cast<const char*>(observed.bytes.data()),observed.bytes.size())==bytes);
#endif
    std::puts("installed Platform/Native: real metadata capture/drain and anonymous publication PASS");
}
