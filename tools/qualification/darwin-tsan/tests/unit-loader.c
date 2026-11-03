#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc,char** argv) {
    const char* path=getenv("CK_TSAN_UNIT_IMAGE");
    if(!path)return 2;
    void* image=dlopen(path,RTLD_NOW|RTLD_LOCAL);
    if(!image){fprintf(stderr,"%s\n",dlerror());return 3;}
    void* symbol=dlsym(image,"main");
    if(!symbol){fprintf(stderr,"%s\n",dlerror());return 4;}
    Dl_info info;
    if(!dladdr(symbol,&info)||!info.dli_fname||strcmp(info.dli_fname,path))return 5;
    fprintf(stderr,"runtime_test_image=%s\n",info.dli_fname);
    int(*entry)(int,char**)=0;
    _Static_assert(sizeof(entry)==sizeof(symbol),"function pointer representation");
    memcpy(&entry,&symbol,sizeof(entry));
    // gtest death tests re-exec argv[0]. Keep the actual executable here;
    // the inherited image variable routes the child through this same loader.
    return entry(argc,argv);
}
