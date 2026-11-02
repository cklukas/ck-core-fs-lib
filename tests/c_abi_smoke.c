#include "ck_file_engine.h"
#include "ck_fs_tree.h"
#include "ck_fs_actions.h"
#include "ck_fs_session.h"

#undef NDEBUG
#include <assert.h>
#include <string.h>

int main(void) {
    ckfe_error error;
    ckfe_error_init(&error);
    assert(strcmp(ckfe_version(), "0.3.0") == 0);
    assert(ckfe_abi_version_major() == 0);
    assert(ckfe_abi_version_minor() == 3);
    assert(strcmp(ckfe_api_status_name(CKFE_API_OK), "ok") == 0);
    assert(strcmp(ckfe_job_state_name(CKFE_JOB_RECOVERY_REQUIRED), "recovery_required") == 0);
    assert(strcmp(ckfe_api_status_name(CKFE_API_OPERATION_UNAVAILABLE), "operation_unavailable") == 0);
    assert(strcmp(ckfe_api_status_name(CKFE_API_STALE_PLAN), "stale_plan") == 0);
    assert(strcmp(ckfe_api_status_name(CKFE_API_BUFFER_TOO_SMALL), "buffer_too_small") == 0);

    ckfe_engine *engine = NULL;
    assert(ckfe_engine_create(&engine) == CKFE_API_OK);
    assert(engine != NULL);
    ckfe_directory *directory = (ckfe_directory *)(uintptr_t)1;
    assert(ckfe_directory_open_utf8(NULL, "/", 0, &directory, &error) == CKFE_API_INVALID_ARGUMENT);
    assert(directory == NULL);
    directory = (ckfe_directory *)(uintptr_t)1;
    assert(ckfe_directory_open_utf16(engine,(const uint16_t *)(uintptr_t)1,SIZE_MAX,0,&directory,&error) == CKFE_API_INVALID_ARGUMENT);
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
    ckfe_copy_options_v2 replay = {2, sizeof(ckfe_copy_options_v2), CKFE_METADATA_COMPLETE_V1,
        0, CKFE_OWNERSHIP_ORIGINAL, 0, {0,0,0,0}};
    replay.allow_privilege_metadata = 2;
    job = (ckfe_job *)(uintptr_t)1;
    assert(ckfe_job_start_copy_regular_v2(NULL,NULL,NULL,NULL,&replay,&job,&error) == CKFE_API_INVALID_ARGUMENT && job == NULL);
    ckfet_options_v1 tree;
    ckfet_options_init_v1(&tree);
    assert(tree.version == CKFET_VERSION && tree.struct_size == sizeof tree);
    ckfet_job *tree_job = (ckfet_job *)(uintptr_t)1;
    assert(ckfet_start_v1(NULL,NULL,&tree,&tree_job,&error) == CKFE_API_INVALID_ARGUMENT && tree_job == NULL);
    ckfet_snapshot_v1 snapshot;
    memset(&snapshot,0xa5,sizeof snapshot);
    assert(ckfet_poll_v1(NULL,&snapshot) == CKFE_API_INVALID_ARGUMENT && snapshot.sequence == 0 && snapshot.plan_generation == 0);
    ckfe_engine_destroy(engine);
    ckfe_error_free(&error);
    return 0;
}
