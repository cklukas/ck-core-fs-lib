// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
#ifndef __linux__
#error This native descriptor interposition fixture is Linux-only.
#endif
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <initializer_list>
#include <stdexcept>
#include <string>
#include <string_view>
#include <fcntl.h>
#include <linux/magic.h>
#include <sys/vfs.h>
#include <unistd.h>
namespace native_finalization_fixture {
inline std::string explicit_root,expected_filesystem;
inline std::string_view parse(int argc,char** argv,std::initializer_list<std::string_view> modes){
 if(argc<2)throw std::runtime_error("expected test mode");
 const std::string_view mode=argv[1];bool found=false;for(auto candidate:modes)found|=candidate==mode;
 if(!found)throw std::runtime_error("unknown test mode");
 if(const auto* e=std::getenv("CK_FS_TEST_EXPECT_FILESYSTEM"))expected_filesystem=e;
 for(int i=2;i<argc;i+=2){if(i+1>=argc)throw std::runtime_error("missing fixture option value");const std::string_view flag=argv[i];if(flag=="--fixture-root")explicit_root=argv[i+1];else if(flag=="--expect-filesystem")expected_filesystem=argv[i+1];else throw std::runtime_error("unknown fixture option");}
 return mode;
}
inline std::string base(){
 if(getuid()==0||geteuid()!=getuid())throw std::runtime_error("native finalization requires an ordinary non-root effective identity");
 std::string root=explicit_root;
 if(root.empty()){const auto* p=std::getenv("TMPDIR");if(!p||!*p)throw std::runtime_error("set explicit TMPDIR or --fixture-root; no system-temp fallback");root=p;}
 if(root.front()!='/')throw std::runtime_error("fixture root must be absolute");
 int fd=::open(root.c_str(),O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);if(fd<0)throw std::runtime_error("open explicit fixture root failed");
 struct statfs info{};const int rc=fstatfs(fd,&info);const int saved=errno;const int closed=::close(fd);if(rc||closed){errno=saved;throw std::runtime_error("inspect fixture filesystem failed");}
 const char* fs=info.f_type==EXT4_SUPER_MAGIC?"ext4":info.f_type==XFS_SUPER_MAGIC?"xfs":info.f_type==BTRFS_SUPER_MAGIC?"btrfs":nullptr;
 if(!fs)throw std::runtime_error("fixture requires qualified native ext4/XFS/Btrfs, not an unknown/overlay provider");
 if(!expected_filesystem.empty()&&expected_filesystem!=fs)throw std::runtime_error("actual fixture filesystem differs from expected filesystem");
 std::printf("native finalization fixture filesystem=%s uid=%lu\n",fs,static_cast<unsigned long>(getuid()));return root;
}
}
