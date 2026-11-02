#include "ck_file_engine.h"
#include "ck_fs_plan.h"
#include "ck_fs_tree.h"
#include "ck_fs_actions.h"
#include "ck_fs_session.h"

#undef NDEBUG
#include <assert.h>
#include <string.h>

int main(void) {
    ckfe_error error;
    ckfe_error_init(&error);
    assert(ckfe_abi_version_major() == 0);
    assert(ckfe_abi_version_minor() >= 3);
    ckfe_engine *engine = NULL;
    assert(ckfe_engine_create(&engine) == CKFE_API_OK);
    assert(engine != NULL);
    ckfe_preservation_policy_v1 policy;
    assert(ckfe_preservation_policy_init_v1(&policy) == CKFE_POLICY_VALID);
    assert(ckfe_preservation_policy_validate_v1(&policy) == CKFE_POLICY_VALID);
    assert(policy.dispositions[CKFE_POLICY_OWNERSHIP] == CKFE_POLICY_CURRENT_CALLER);
    assert(policy.dispositions[CKFE_POLICY_PRIVILEGE_BITS] == CKFE_POLICY_DISCARD_SOURCE);
    policy.flags = UINT32_MAX;
    assert(ckfe_preservation_policy_validate_v1(&policy) == CKFE_POLICY_UNKNOWN_FIELD);
    ckfsp_input input;
    ckfsp_input_init(&input);
    assert(input.version == CKFSP_VERSION && input.struct_size == sizeof(input));
    assert(strcmp(ckfe_api_status_name(CKFE_API_OPERATION_UNAVAILABLE), "operation_unavailable") == 0);
    ckfet_options_v1 tree;
    ckfet_options_init_v1(&tree);
    assert(tree.version == CKFET_VERSION && tree.struct_size == sizeof tree);
    ckfea_request actions;
    ckfea_request_init(&actions);
    assert(actions.version == CKFEA_VERSION && actions.struct_size == sizeof actions);
    ckfss_metadata_policy metadata;
    ckfss_metadata_policy_init(&metadata);
    assert(metadata.version == CKFSS_VERSION && metadata.struct_size == sizeof metadata);
    ckfe_engine_destroy(engine);
    ckfe_error_free(&error);
    return 0;
}
