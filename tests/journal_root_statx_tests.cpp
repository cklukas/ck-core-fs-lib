// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "native_filesystem.hpp"
#include "prepared_journal_root.hpp"
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <sys/stat.h>

using namespace ck::files;
namespace {
enum class Fault { None, MissingType, MissingInode, MissingLinks, MissingMount,
    Permission, NotImplemented, Io, Inode, Device, ZeroLinks, Kind, Mount };
Fault armed=Fault::None;
bool parent_edge=false;
unsigned intercepted=0;
constexpr unsigned required=STATX_TYPE|STATX_INO|STATX_NLINK|STATX_MNT_ID;
template<class T>T take(Observation<T> result) {
    if(!result.value()) {
        std::fprintf(stderr,"Root statx fixture: %s\n",result.unavailable_detail()->error.operation.c_str());
        std::abort();
    }
    return std::move(result).take_value();
}
}
// Link-time interception in this test executable only. Always perform the
// actual native observation first; inject only a failure or corrupt one result.
// Requested-mask matching isolates the combined Root node observations from
// private ACL, named membership and other native metadata queries.
extern "C" int __real_statx(int,const char*,int,unsigned,struct statx*);
extern "C" int __wrap_statx(int fd,const char* path,int flags,unsigned mask,struct statx* value) {
    const int result=__real_statx(fd,path,flags,mask,value);
    if(result||armed==Fault::None||mask!=required||parent_edge!=(std::strcmp(path,"..")==0))return result;
    const auto fault=armed;armed=Fault::None;++intercepted;
    switch(fault) {
    case Fault::MissingType:value->stx_mask&=~STATX_TYPE;break;
    case Fault::MissingInode:value->stx_mask&=~STATX_INO;break;
    case Fault::MissingLinks:value->stx_mask&=~STATX_NLINK;break;
    case Fault::MissingMount:value->stx_mask&=~STATX_MNT_ID;break;
    case Fault::Permission:errno=EACCES;return -1;
    case Fault::NotImplemented:errno=ENOSYS;return -1;
    case Fault::Io:errno=EIO;return -1;
    case Fault::Inode:value->stx_ino^=1;break;
    case Fault::Device:value->stx_dev_minor^=1;break;
    case Fault::ZeroLinks:value->stx_nlink=0;break;
    case Fault::Kind:value->stx_mode=(value->stx_mode&~S_IFMT)|S_IFREG;break;
    case Fault::Mount:value->stx_mnt_id^=1;break;
    case Fault::None:break;
    }
    return result;
}
int main(int argc,char** argv) {
    assert(argc==2);
    NativeFileSystem fs;
    const auto address=take(NativeAbsolutePath::from_posix(argv[1]));
    auto parent=std::shared_ptr<const DirectoryCursor>(take(fs.open_native_directory(address)));
    PreparedJournalRootRequest request;
    request.parent=parent;request.child=*NativeName::from_posix("journal-statx");
    request.disposition=JournalRootDisposition::ProvisionChild;
    JournalRootPreparationProgress progress;
    auto root=take(prepare_native_journal_root(std::move(request),progress));
    assert(progress.directory_creates==1&&take(root->revalidate()));
    for(const bool ancestor:{false,true})for(const auto fault:{Fault::MissingType,Fault::MissingInode,
        Fault::MissingLinks,Fault::MissingMount,Fault::Permission,Fault::NotImplemented,Fault::Io,
        Fault::Inode,Fault::Device,Fault::ZeroLinks,Fault::Kind,Fault::Mount}) {
        parent_edge=ancestor;armed=fault;const auto before=intercepted;
        auto checked=root->revalidate();
        assert(intercepted==before+1&&armed==Fault::None&&!checked.value());
        const auto& error=*checked.unavailable_detail();
        if(fault<=Fault::MissingMount) {
            assert(error.state==ObservationState::Unsupported&&error.error.domain==ErrorDomain::Adapter&&
                error.error.code==static_cast<std::int64_t>(AdapterError::UnsupportedQuery));
        } else if(fault<=Fault::Io) {
            const auto code=fault==Fault::Permission?EACCES:fault==Fault::NotImplemented?ENOSYS:EIO;
            const auto state=fault==Fault::Permission?ObservationState::Denied:
                fault==Fault::NotImplemented?ObservationState::Unsupported:ObservationState::Failed;
            assert(error.state==state&&error.error.domain==ErrorDomain::Posix&&error.error.code==code);
            assert(error.error.operation==(ancestor?"journal_root.ancestor_edge":"journal_root.held_identity"));
        } else {
            assert(error.state==ObservationState::Changed&&error.error.domain==ErrorDomain::Adapter&&
                error.error.code==static_cast<std::int64_t>(AdapterError::MetadataChanged));
            const auto tag=fault==Fault::Mount?(ancestor?"journal_root.ancestor_mount_changed":"journal_root.held_mount_changed"):
                (ancestor?"journal_root.ancestor_changed":"journal_root.held_identity_changed");
            assert(error.error.operation==tag);
        }
        assert(take(root->revalidate()));
    }
    assert(intercepted==24&&take(root->finish_io()));
    std::puts("Root combined statx: 24 held/parent missing-field, error and changed-object refusals passed");
}
