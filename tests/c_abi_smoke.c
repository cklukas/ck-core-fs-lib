#include "ck_file_engine.h"

#undef NDEBUG
#include <assert.h>
#include <string.h>

int main(void) {
    ckfe_error error;
    ckfe_error_init(&error);
    assert(strcmp(ckfe_version(), "0.2.0") == 0);
    assert(ckfe_abi_version_major() == 0);
    assert(ckfe_abi_version_minor() == 2);
    assert(strcmp(ckfe_api_status_name(CKFE_API_OK), "ok") == 0);
    assert(strcmp(ckfe_job_state_name(CKFE_JOB_RECOVERY_REQUIRED), "recovery_required") == 0);
    assert(strcmp(ckfe_api_status_name(CKFE_API_OPERATION_UNAVAILABLE), "operation_unavailable") == 0);

    ckfe_engine *engine = NULL;
    assert(ckfe_engine_create(&engine) == CKFE_API_OK);
    assert(engine != NULL);
    ckfe_directory *directory = (ckfe_directory *)(uintptr_t)1;
    assert(ckfe_directory_open_utf8(NULL, "/", 0, &directory, &error) == CKFE_API_INVALID_ARGUMENT);
    assert(directory == NULL);
    ckfe_metadata metadata;
    memset(&metadata, 0xa5, sizeof metadata);
    assert(ckfe_entry_metadata(NULL, &metadata, &error) == CKFE_API_INVALID_ARGUMENT);
    assert(metadata.available_fields == 0);
    size_t count = 42;
    uint64_t coalesced = 42;
    assert(ckfe_job_drain_events(NULL, NULL, 0, &count, &coalesced, &error) == CKFE_API_INVALID_ARGUMENT);
    assert(count == 0 && coalesced == 0);
    ckfe_recovery *recovery = (ckfe_recovery *)(uintptr_t)1;
    assert(ckfe_recovery_open_utf8(NULL, NULL, &recovery, &error) == CKFE_API_INVALID_ARGUMENT);
    assert(recovery == NULL);
    ckfe_recovery_summary summary;
    memset(&summary, 0xa5, sizeof summary);
    assert(ckfe_recovery_get_summary(NULL, &summary, &error) == CKFE_API_INVALID_ARGUMENT);
    assert(summary.items == 0 && summary.untrusted_tail == 0);
    count = 42;
    assert(ckfe_recovery_read_page(NULL, 0, NULL, 0, &count, &error) == CKFE_API_INVALID_ARGUMENT);
    assert(count == 0);
    ckfe_copy_options_v1 options = {CKFE_COPY_OPTIONS_VERSION, sizeof(ckfe_copy_options_v1),
        CKFE_METADATA_ORDINARY_CALLER_VISIBLE_V1, 0, {0,0,0,0}};
    ckfe_job *job = (ckfe_job *)(uintptr_t)1;
    options.reserved[0] = 1;
    assert(ckfe_job_start_copy_regular_v1(NULL, NULL, NULL, NULL, &options, &job, &error) == CKFE_API_INVALID_ARGUMENT);
    assert(job == NULL);
    options.reserved[0] = 0;
    options.version = 2;
    assert(ckfe_job_start_copy_regular_v1(NULL, NULL, NULL, NULL, &options, &job, &error) == CKFE_API_INVALID_ARGUMENT);
    options.version = 1;
    options.metadata_scope = UINT32_MAX;
    assert(ckfe_job_start_copy_regular_v1(NULL, NULL, NULL, NULL, &options, &job, &error) == CKFE_API_INVALID_ARGUMENT);
    ckfe_engine_destroy(engine);
    ckfe_error_free(&error);
    return 0;
}
