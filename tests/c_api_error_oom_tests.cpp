// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "ck_file_engine.h"
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <new>
namespace { std::atomic<bool> deny{false};unsigned attempts=0; }
void* operator new(std::size_t size) {
    if(deny){++attempts;throw std::bad_alloc();}
    if(void* p=std::malloc(size?size:1))return p;
    throw std::bad_alloc();
}
void* operator new[](std::size_t size){return ::operator new(size);}
void operator delete(void* p)noexcept{std::free(p);}
void operator delete[](void* p)noexcept{std::free(p);}
void operator delete(void* p,std::size_t)noexcept{std::free(p);}
void operator delete[](void* p,std::size_t)noexcept{std::free(p);}
int main() {
    std::set_terminate([]{deny=false;std::fputs("FAIL C error reporting terminated under C++ OOM\n",stderr);std::_Exit(3);});
    ckfe_engine* engine=nullptr;ckfe_directory* directory=nullptr;ckfe_error error{};
    if(ckfe_engine_create(&engine)!=CKFE_API_OK||!engine)return 1;
    ckfe_error_init(&error);
    deny=true;
    const auto status=ckfe_directory_open_utf8(engine,nullptr,0,&directory,&error);
    deny=false;
    // The invalid-input path needs no C++ allocation, native filesystem call,
    // or process-local exception. Diagnostic C allocation may return null.
    const bool passed=status==CKFE_API_INVALID_ARGUMENT&&!directory&&attempts==0&&
        error.state==CKFE_OBSERVATION_FAILED&&error.domain==CKFE_ERROR_ADAPTER&&
        error.code!=0&&(!error.operation||std::strcmp(error.operation,"c_api.directory_path")==0);
    ckfe_error_free(&error);ckfe_engine_destroy(engine);
    std::puts(passed?"PASS exception-free C error reporting under persistent C++ allocation exhaustion":"FAIL C error reporting contract");
    return passed?0:1;
}
