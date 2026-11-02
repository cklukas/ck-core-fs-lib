#include "ck_file_engine.h"

#include <assert.h>
#include <string.h>

int main(void) {
    ckfe_error error;
    ckfe_error_init(&error);
    assert(strcmp(ckfe_version(), "0.1.0") == 0);
    assert(strcmp(ckfe_api_status_name(CKFE_API_OK), "ok") == 0);
    assert(strcmp(ckfe_job_state_name(CKFE_JOB_RECOVERY_REQUIRED), "recovery_required") == 0);

    ckfe_engine *engine = NULL;
    assert(ckfe_engine_create(&engine) == CKFE_API_OK);
    assert(engine != NULL);
    ckfe_engine_destroy(engine);
    ckfe_error_free(&error);
    return 0;
}
