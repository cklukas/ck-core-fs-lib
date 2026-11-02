#include "ck_file_engine.h"

#include <assert.h>
#include <string.h>

int main(void) {
    ckfe_error error;
    ckfe_error_init(&error);
    assert(ckfe_abi_version_major() == 0);
    assert(ckfe_abi_version_minor() == 1);
    ckfe_engine *engine = NULL;
    assert(ckfe_engine_create(&engine) == CKFE_API_OK);
    assert(engine != NULL);
    assert(strcmp(ckfe_api_status_name(CKFE_API_OPERATION_UNAVAILABLE), "operation_unavailable") == 0);
    ckfe_engine_destroy(engine);
    ckfe_error_free(&error);
    return 0;
}
