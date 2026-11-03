// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
// Runtime qualification: replaceable allocation, OOM injection, actual runtime
// image identity and an intentional heap race must all remain observable.
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <new>
#include <sched.h>
#include <sys/stat.h>
#include <thread>
extern "C" void __tsan_init();
namespace {std::atomic<bool> fail_once{false};}
void* operator new(std::size_t bytes) {
    if(fail_once.exchange(false,std::memory_order_relaxed))throw std::bad_alloc();
    if(void* p=std::malloc(bytes?bytes:1))return p;
    throw std::bad_alloc();
}
void* operator new[](std::size_t bytes){return ::operator new(bytes);}
void operator delete(void* p) noexcept {std::free(p);}
void operator delete[](void* p) noexcept {std::free(p);}
void operator delete(void* p,std::size_t) noexcept {std::free(p);}
void operator delete[](void* p,std::size_t) noexcept {std::free(p);}
int main(int argc,char** argv) {
    if(argc!=3)return 10;
    Dl_info image{};struct stat actual{},expected{};
    if(!dladdr(reinterpret_cast<void*>(__tsan_init),&image)||!image.dli_fname||
        stat(image.dli_fname,&actual)||stat(argv[2],&expected)||
        actual.st_dev!=expected.st_dev||actual.st_ino!=expected.st_ino)return 11;
    fail_once.store(true,std::memory_order_relaxed);
    bool refused=false;
    try {void* p=::operator new(64);::operator delete(p);}
    catch(const std::bad_alloc&){refused=true;}
    if(!refused||fail_once.load(std::memory_order_relaxed))return 12;
    std::printf("TSAN_ALLOCATOR_CONTROL_PASS runtime=%s\n",image.dli_fname);std::fflush(stdout);
    if(std::strcmp(argv[1],"clean")==0)return 0;
    if(std::strcmp(argv[1],"race"))return 13;
    auto* value=new int(0);
    std::atomic<bool> written{false},finish{false};
    std::thread worker([&]{
        *value=1;
        written.store(true,std::memory_order_relaxed);
        while(!finish.load(std::memory_order_relaxed))sched_yield();
    });
    while(!written.load(std::memory_order_relaxed))sched_yield();
    *value=2; // Deliberately unordered with the worker, while both are live.
    finish.store(true,std::memory_order_relaxed);
    worker.join();delete value;
    return 0;
}
