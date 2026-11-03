// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#if !defined(__linux__)
#error Linux native fixture only
#endif
#include "native_filesystem.hpp"
#include "native_operation_copy_job.hpp"
#include "platform/linux_ordinary_metadata.hpp"
#include <array>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/xattr.h>
#include <linux/capability.h>
#include <unistd.h>
using namespace ck::files;
using Cursor=std::shared_ptr<const DirectoryCursor>;
namespace {
unsigned checks=0;
#define CHECK(x) do{++checks;if(!(x)){std::fprintf(stderr,"CHECK line%d: %s errno%d\n",__LINE__,#x,errno);std::abort();}}while(false)
template<class T> T take(Observation<T> value){if(!value.value()){const auto& e=*value.unavailable_detail();std::fprintf(stderr,"native operation=%s domain=%u code=%lld state=%u\n",e.error.operation.c_str(),unsigned(e.error.domain),(long long)e.error.code,unsigned(e.state));}CHECK(value.value());return std::move(value).take_value();}
NativeName name(const std::string& text){auto n=NativeName::from_posix(text);CHECK(n);return *n;}
const unsigned char acl[]={2,0,0,0,1,0,6,0,255,255,255,255,2,0,4,0,233,3,0,0,4,0,4,0,255,255,255,255,16,0,4,0,255,255,255,255,32,0,0,0,255,255,255,255};
const std::array<unsigned char,8> attribute={1,0,2,0xff,0,7,8,9};
const std::string attribute_name="user.binary."+std::string(1,char(0xff));
std::vector<std::byte> payload(){std::vector<std::byte> b(3*65536+17);for(std::size_t i=0;i<b.size();++i)b[i]=std::byte((i*137+19)%251+1);return b;}
void decoder(){using namespace detail;using P=LinuxOrdinaryMetadataProvider;CHECK(linux_ordinary_metadata_provider(XFS_SUPER_MAGIC)==P::Xfs);CHECK(linux_ordinary_metadata_provider(BTRFS_SUPER_MAGIC)==P::Btrfs);CHECK(linux_ordinary_metadata_provider(OVERLAYFS_SUPER_MAGIC)==P::Unknown);CHECK(linux_ordinary_metadata_provider(0x12345678)==P::Unknown);
 for(auto p:{P::Unknown,P::Ext4,P::Xfs,P::Btrfs}){CHECK(linux_ordinary_inode_flags(p,0)==(p!=P::Unknown));fsxattr empty{};CHECK(linux_ordinary_storage_policy(p,empty)==(p!=P::Unknown));for(unsigned bit=0;bit<32;++bit){const std::uint32_t mask=std::uint32_t{1}<<bit;CHECK(linux_ordinary_inode_flags(p,mask)==(p==P::Ext4&&mask==FS_EXTENT_FL));fsxattr x{};x.fsx_xflags=mask;CHECK(linux_ordinary_storage_policy(p,x)==(p==P::Xfs&&mask==FS_XFLAG_HASATTR));}
  for(unsigned field=0;field<3;++field){fsxattr x{};if(field==0)x.fsx_projid=1;if(field==1)x.fsx_extsize=1;if(field==2)x.fsx_cowextsize=1;CHECK(!linux_ordinary_storage_policy(p,x));}}
 CHECK(linux_ordinary_inode_flags(P::Ext4,FS_INDEX_FL,true));CHECK(!linux_ordinary_inode_flags(P::Ext4,FS_INDEX_FL,false));}
struct Fixture{NativeFileSystem fs;Cursor root;NativeAbsolutePath address;int fd=-1;unsigned id=0;explicit Fixture(const char* raw):address(take(NativeAbsolutePath::from_posix(raw))){root=Cursor(take(fs.open_native_directory(address)));fd=open(raw,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);CHECK(fd>=0);}~Fixture(){if(fd>=0)CHECK(close(fd)==0);}
 void file(int parent,const std::string& leaf,bool attributes){int f=openat(parent,leaf.c_str(),O_RDWR|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0640);CHECK(f>=0);auto bytes=payload();CHECK(write(f,bytes.data(),bytes.size())==ssize_t(bytes.size()));if(attributes){CHECK(fsetxattr(f,attribute_name.c_str(),attribute.data(),attribute.size(),0)==0);CHECK(fsetxattr(f,"system.posix_acl_access",acl,sizeof(acl),0)==0);}timespec times[2]={{1600000000,123456789},{1600000100,987654321}};CHECK(fchmod(f,0640)==0);CHECK(futimens(f,times)==0);CHECK(fsync(f)==0);CHECK(close(f)==0);}
 Observation<OperationBatchJob::Pointer> copy(Cursor parent,const std::string& from,const std::string& to){NativeOperationCopyBatchRequest request;request.sources={take(HeldChild::observe(parent,name(from)))};request.destination=parent;request.destination_names={name(to)};request.journal_root=address;request.journal_id.bytes[0]=std::byte(++id);request.policy.metadata_scope=RegularMetadataScope::OrdinaryCallerVisibleV1;request.open_journal=open_native_operation_journal_file;return create_native_operation_copy_batch(std::move(request));}
 void complete(Cursor parent,const std::string& from,const std::string& to,int parentfd,bool attributes){auto job=take(copy(parent,from,to));for(unsigned i=0;i<100000&&(job->state()==OperationBatchState::Ready||job->state()==OperationBatchState::Running);++i)job->advance();if(job->state()!=OperationBatchState::Complete)for(const auto& item:job->result().items)if(item.failure)std::fprintf(stderr,"copy failed %s code%lld\n",item.failure->error.operation.c_str(),(long long)item.failure->error.code);CHECK(job->state()==OperationBatchState::Complete);int target=openat(parentfd,to.c_str(),O_RDONLY|O_CLOEXEC|O_NOFOLLOW);CHECK(target>=0);struct stat st{};CHECK(fstat(target,&st)==0);CHECK(st.st_uid==1000&&st.st_gid==1000&&(st.st_mode&07777)==0640);CHECK(st.st_atim.tv_sec==1600000000&&st.st_atim.tv_nsec==123456789&&st.st_mtim.tv_sec==1600000100&&st.st_mtim.tv_nsec==987654321);if(attributes){std::array<unsigned char,256> bytes{};CHECK(fgetxattr(target,attribute_name.c_str(),bytes.data(),bytes.size())==ssize_t(attribute.size()));CHECK(std::memcmp(bytes.data(),attribute.data(),attribute.size())==0);CHECK(fgetxattr(target,"system.posix_acl_access",bytes.data(),bytes.size())==ssize_t(sizeof(acl)));CHECK(std::memcmp(bytes.data(),acl,sizeof(acl))==0);}auto expected=payload();std::vector<std::byte> bytes(expected.size());std::size_t offset=0;while(offset<bytes.size()){auto n=read(target,bytes.data()+offset,bytes.size()-offset);CHECK(n>0);offset+=std::size_t(n);}CHECK(bytes==expected);CHECK(close(target)==0);}
 void refused(const std::string& from,const std::string& to){auto result=copy(root,from,to);CHECK(!result.value());CHECK(result.unavailable_detail()->error.domain==ErrorDomain::Adapter&&result.unavailable_detail()->error.code==std::int64_t(AdapterError::ProviderReviewRequired));CHECK(take(root->lookup_child(name(to),ChildLookupMode::NativeDefault)).state()==ChildLookupState::Missing);}
};
void native(const char* raw){Fixture f(raw);f.file(f.fd,"plain",false);auto held=take(HeldChild::observe(f.root,name("plain")));CHECK(take(held->qualify_ordinary_regular_metadata()));f.complete(f.root,"plain","plain-copy",f.fd,false);f.file(f.fd,"attributes",true);MetadataReplayPolicy ordinary;ordinary.scope=RegularMetadataScope::OrdinaryCallerVisibleV1;ordinary.ownership=MetadataOwnership::CurrentCaller;auto attributes=take(HeldChild::observe(f.root,name("attributes")));auto snapshot=take(attributes->capture_metadata(ordinary));CHECK(snapshot.attributes.size()>=2);f.complete(f.root,"attributes","attributes-copy",f.fd,true);
 auto complete=ordinary;complete.scope=RegularMetadataScope::CompleteMetadataV1;auto denied=held->capture_metadata(complete);CHECK(!denied.value()&&denied.state()==ObservationState::Unsupported);
 f.file(f.fd,"unreadable",false);CHECK(fchmodat(f.fd,"unreadable",0000,0)==0);f.refused("unreadable","unreadable-copy");CHECK(fchmodat(f.fd,"unreadable",0640,0)==0);
 f.file(f.fd,"nodump",false);int flagsfd=openat(f.fd,"nodump",O_RDONLY|O_CLOEXEC);CHECK(flagsfd>=0);int flags=0;CHECK(ioctl(flagsfd,FS_IOC_GETFLAGS,&flags)==0);flags|=FS_NODUMP_FL;CHECK(ioctl(flagsfd,FS_IOC_SETFLAGS,&flags)==0);CHECK(close(flagsfd)==0);f.refused("nodump","nodump-copy");
 auto capability=f.root->lookup_child(name("administrative-capability-source"),ChildLookupMode::NativeDefault);CHECK(take(std::move(capability)).state()==ChildLookupState::Found);f.refused("administrative-capability-source","capability-copy");
 CHECK(mkdirat(f.fd,"directory",0700)==0);int d=openat(f.fd,"directory",O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);CHECK(d>=0);CHECK(fsetxattr(d,attribute_name.c_str(),attribute.data(),attribute.size(),0)==0);CHECK(fsetxattr(d,"system.posix_acl_default",acl,sizeof(acl),0)==0);CHECK(close(d)==0);auto dir=take(f.root->open_child(name("directory"),EntryAccess::MetadataAndAttributes|EntryAccess::MetadataAndSecurity));auto catalog=take(dir->inspect_attributes());CHECK(catalog.attributes.size()>=2);auto default_acl=take(dir->read_security(SecurityPart::LinuxDefaultAcl));CHECK(default_acl.presence==SecurityPresence::Present&&default_acl.bytes.size()==sizeof(acl)&&std::memcmp(default_acl.bytes.data(),acl,sizeof(acl))==0);CHECK(!dir->qualify_metadata_replay(ordinary).value());
 Cursor cursor=f.root;int fd=dup(f.fd);CHECK(fd>=0);std::size_t total=std::strlen(raw);for(unsigned i=0;i<23;++i){const std::string leaf="long-"+std::to_string(i)+std::string(180,'x');cursor=Cursor(take(cursor->create_child_directory(name(leaf))));int next=openat(fd,leaf.c_str(),O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);CHECK(next>=0);CHECK(close(fd)==0);fd=next;total+=1+leaf.size();}CHECK(total>4096);std::string exact="source-";exact.push_back(char(0xff));exact+="-\n;'$()";std::string target="target-";target.push_back(char(0xfe));target+="-\n;'$()";f.file(fd,exact,true);f.complete(cursor,exact,target,fd,true);CHECK(close(fd)==0);
}
}
int main(int argc,char** argv){if(argc==2&&std::strcmp(argv[1],"--policy")==0){decoder();std::printf("linux ordinary metadata policy: %u checks passed\n",checks);return 0;}CHECK(argc==2&&getuid()==1000&&geteuid()==1000);__user_cap_header_struct h{};h.version=_LINUX_CAPABILITY_VERSION_3;__user_cap_data_struct c[2]{};CHECK(syscall(SYS_capget,&h,c)==0);CHECK(c[0].effective==0&&c[0].permitted==0&&c[0].inheritable==0&&c[1].effective==0&&c[1].permitted==0&&c[1].inheritable==0);CHECK(prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)==1);decoder();native(argv[1]);std::printf("linux ordinary metadata: %u checks passed\n",checks);}
