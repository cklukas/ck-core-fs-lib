// SPDX-License-Identifier: LGPL-2.0-or-later
#include <ck_file_engine.h>
#include <ck_fs_tree.h>
#include <cassert>
#include <cstdio>
int main(int argc,char**argv){
    assert(argc==2);ckfe_engine* engine=nullptr;ckfe_directory* directory=nullptr;ckfe_entry* entry=nullptr;
    ckfe_error error{};ckfe_error_init(&error);
    assert(ckfe_engine_create(&engine)==CKFE_API_OK);
    assert(ckfe_directory_open_utf8(engine,argv[1],0,&directory,&error)==CKFE_API_OK);
    assert(ckfe_entry_open_utf8(directory,"input",&entry,&error)==CKFE_API_OK);
    ckfe_metadata metadata{};assert(ckfe_entry_metadata(entry,&metadata,&error)==CKFE_API_OK);
    assert((metadata.available_fields&CKFE_METADATA_LOGICAL_SIZE)&&metadata.logical_size==19);
    ckfet_name_feedback_v1 feedback{};
    assert(ckfet_name_feedback_get_v1(nullptr,1,1,CKFET_RENAME,&feedback)==CKFE_API_INVALID_ARGUMENT);
    ckfe_entry_destroy(entry);ckfe_directory_destroy(directory);ckfe_engine_destroy(engine);ckfe_error_free(&error);
    std::puts("installed C API: native directory/entry metadata and additive getter PASS");
}
