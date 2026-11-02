// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#ifndef CK_FS_POLICY_H
#define CK_FS_POLICY_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32) && !defined(CK_FS_POLICY_STATIC)
# if defined(CK_FILE_ENGINE_BUILD)
#  define CK_FS_POLICY_API __declspec(dllexport)
# else
#  define CK_FS_POLICY_API __declspec(dllimport)
# endif
#elif defined(__GNUC__)
# define CK_FS_POLICY_API __attribute__((visibility("default")))
#else
# define CK_FS_POLICY_API
#endif

#ifdef __cplusplus
# define CK_FS_POLICY_NOEXCEPT noexcept
extern "C" {
#else
# define CK_FS_POLICY_NOEXCEPT
#endif

#define CKFE_PRESERVATION_POLICY_VERSION 1u
#define CKFE_POLICY_ORDINARY_MODE_MASK 0777u
#define CKFE_POLICY_PRIVILEGE_MODE_MASK 07000u

// Fixed-width fields carry these constants; no compiler-sized enums cross ABI.
typedef uint32_t ckfe_preservation_class;
enum {
    CKFE_POLICY_ORDINARY_PERMISSIONS = 0,
    CKFE_POLICY_TIMESTAMPS = 1,
    CKFE_POLICY_OWNERSHIP = 2,
    CKFE_POLICY_ACCESS_ACL = 3,
    CKFE_POLICY_DEFAULT_ACL = 4,
    CKFE_POLICY_XATTRS = 5,
    CKFE_POLICY_SECURITY_LABELS = 6,
    CKFE_POLICY_CAPABILITIES = 7,
    CKFE_POLICY_PRIVILEGE_BITS = 8,
    CKFE_POLICY_STORAGE = 9,
    CKFE_POLICY_PROVIDER = 10,
    CKFE_POLICY_ADDITIONAL_DATA = 11,
    CKFE_POLICY_LINKS = 12,
    CKFE_POLICY_CLASS_COUNT = 13
};
#define CKFE_POLICY_ALL_CLASSES ((UINT64_C(1) << CKFE_POLICY_CLASS_COUNT) - UINT64_C(1))

typedef uint32_t ckfe_preservation_disposition;
enum {
    CKFE_POLICY_DISPOSITION_UNSPECIFIED = 0, // Invalid, including zero initialization.
    CKFE_POLICY_REQUIRE_SOURCE = 1,
    CKFE_POLICY_DISCARD_SOURCE = 2, // Explicit loss, always reported when present.
    CKFE_POLICY_REVIEW = 3,
    CKFE_POLICY_CURRENT_CALLER = 4 // Only valid for OWNERSHIP; not source uid/gid/SID.
};
enum {
    CKFE_POLICY_ALLOW_PRIVILEGE_REPLAY = 1u << 0,
    CKFE_POLICY_ALLOW_CAPABILITY_REPLAY = 1u << 1
};

typedef uint32_t ckfe_policy_validation;
enum {
    CKFE_POLICY_VALID = 0,
    CKFE_POLICY_INVALID_ARGUMENT = 1,
    CKFE_POLICY_INVALID_VERSION = 2,
    CKFE_POLICY_INVALID_STRUCT_SIZE = 3,
    CKFE_POLICY_UNKNOWN_FIELD = 4,
    CKFE_POLICY_INVALID_DISPOSITION = 5,
    CKFE_POLICY_PRIVILEGE_OPT_IN_REQUIRED = 6,
    CKFE_POLICY_INVALID_EVIDENCE = 7
};

typedef struct ckfe_preservation_policy_v1 {
    uint32_t version;
    uint32_t struct_size;
    uint32_t flags;
    uint32_t reserved;
    ckfe_preservation_disposition dispositions[CKFE_POLICY_CLASS_COUNT];
    uint32_t reserved_words[3];
} ckfe_preservation_policy_v1;

typedef uint32_t ckfe_policy_source_state;
enum {
    CKFE_POLICY_SOURCE_UNKNOWN = 0,
    CKFE_POLICY_SOURCE_ABSENT = 1,
    CKFE_POLICY_SOURCE_PRESENT = 2,
    CKFE_POLICY_SOURCE_UNSUPPORTED = 3,
    CKFE_POLICY_SOURCE_DENIED = 4,
    CKFE_POLICY_SOURCE_CHANGED = 5,
    CKFE_POLICY_SOURCE_NEEDS_REVIEW = 6
};
typedef uint32_t ckfe_policy_support;
enum {
    CKFE_POLICY_SUPPORT_UNKNOWN = 0,
    CKFE_POLICY_SUPPORT_SUPPORTED = 1,
    CKFE_POLICY_SUPPORT_UNSUPPORTED = 2,
    CKFE_POLICY_SUPPORT_DENIED = 3,
    CKFE_POLICY_SUPPORT_CHANGED = 4,
    CKFE_POLICY_SUPPORT_NEEDS_REVIEW = 5
};
typedef uint32_t ckfe_policy_inventory_state;
enum {
    CKFE_POLICY_INVENTORY_UNKNOWN = 0,
    CKFE_POLICY_INVENTORY_COMPLETE = 1,
    CKFE_POLICY_INVENTORY_UNSUPPORTED = 2,
    CKFE_POLICY_INVENTORY_DENIED = 3,
    CKFE_POLICY_INVENTORY_CHANGED = 4,
    CKFE_POLICY_INVENTORY_NEEDS_REVIEW = 5
};
enum {
    CKFE_POLICY_EVIDENCE_COMPLETE = 1u << 0,
    CKFE_POLICY_INVENTORY_SECURITY_CLASSIFIED = 1u << 0
};

typedef struct ckfe_preservation_class_evidence_v1 {
    ckfe_policy_source_state source;
    // Qualified ability to implement THIS disposition for THIS held object,
    // including permissions/rights and exact representation. A volume feature
    // advertisement alone is insufficient. CURRENT_CALLER tests caller ownership.
    ckfe_policy_support destination;
    // Complete catalog AND values across the whole class, not merely one query
    // or record. Partial evidence must never be marked complete.
    uint32_t flags;
    uint32_t reserved;
} ckfe_preservation_class_evidence_v1;

// Evidence supplied by a trusted worker, not a serialized wire format. No I/O
// occurs here. COMPLETE attests full aggregate coverage of all held objects,
// including names/membership, identities and metadata continuity. Attempting
// every query is insufficient. Revalidate before mutation; this is no receipt.
// Every class requires explicit complete presence/absence, including irrelevant
// platform families (qualified absence). Unknown is never inferred as absent.
// SECURITY_CLASSIFIED attests that ordinary permissions exclude 07000, and
// generic xattrs exclude ACLs, labels, capabilities and provider/storage data.
// Unknown namespaces/flags, opaque descriptors with unseparated owner/ACL/label
// fields, unclassified security xattrs and privilege-affecting inode flags must
// block classification or be represented by the appropriate class as review.
// LINKS covers link/reparse payload/semantics; ADDITIONAL_DATA covers named
// streams/forks. STORAGE includes allocation, compression/encryption and inode
// flags. Main-data verification is a separate execution requirement.
typedef struct ckfe_preservation_inventory_v1 {
    uint32_t version;
    uint32_t struct_size;
    ckfe_policy_inventory_state state;
    uint32_t flags;
    ckfe_preservation_class_evidence_v1 classes[CKFE_POLICY_CLASS_COUNT];
    uint32_t reserved_words[4];
} ckfe_preservation_inventory_v1;

typedef uint32_t ckfe_policy_result;
enum {
    CKFE_POLICY_RESULT_INVALID = 0,
    CKFE_POLICY_RESULT_SUPPORTED = 1,
    CKFE_POLICY_RESULT_UNSUPPORTED = 2,
    CKFE_POLICY_RESULT_DENIED = 3,
    CKFE_POLICY_RESULT_CHANGED = 4,
    CKFE_POLICY_RESULT_NEEDS_REVIEW = 5
};

typedef struct ckfe_preservation_assessment_v1 {
    uint32_t version;
    uint32_t struct_size;
    ckfe_policy_result result;
    ckfe_policy_validation validation;
    uint32_t inventory_complete; // 0/1; never true on invalid/partial observations.
    uint32_t reserved;
    // Masks preserve ALL findings; result summarizes by priority:
    // INVALID > CHANGED > DENIED > UNSUPPORTED > NEEDS_REVIEW > SUPPORTED.
    uint64_t supported_classes;
    uint64_t discarded_classes;
    uint64_t unsupported_classes;
    uint64_t denied_classes;
    uint64_t changed_classes;
    uint64_t needs_review_classes;
    uint64_t incomplete_classes;
} ckfe_preservation_assessment_v1;

// Initialize full v1 objects before use. Null returns INVALID_ARGUMENT. Defaults:
// require ordinary permissions, timestamps, streams and links; current caller
// owns new objects; discard special mode bits; review all remaining classes.
// DISCARD_SOURCE never means erase inherited/destination metadata, and is not
// authorization to publish. Inherited ACLs, umasks, labels and defaults still
// require native verification. No profile silently replays source privilege.
CK_FS_POLICY_API ckfe_policy_validation ckfe_preservation_policy_init_v1(
    ckfe_preservation_policy_v1 *policy) CK_FS_POLICY_NOEXCEPT;
CK_FS_POLICY_API ckfe_policy_validation ckfe_preservation_inventory_init_v1(
    ckfe_preservation_inventory_v1 *inventory) CK_FS_POLICY_NOEXCEPT;

// Exact version AND exact struct_size required. Unknown enums, flags, reserved
// fields, larger future structures and truncated structures fail closed.
CK_FS_POLICY_API ckfe_policy_validation ckfe_preservation_policy_validate_v1(
    const ckfe_preservation_policy_v1 *policy) CK_FS_POLICY_NOEXCEPT;
CK_FS_POLICY_API ckfe_policy_validation ckfe_preservation_inventory_validate_v1(
    const ckfe_preservation_inventory_v1 *inventory) CK_FS_POLICY_NOEXCEPT;

// Pure, allocation-free and exception-free. Output storage must be disjoint
// from input and exactly sizeof(v1); on invalid output pointer/size no bytes
// are written. Other invalid inputs produce a fully initialized INVALID output.
// SUPPORTED means policy-compatible evidence, not applied/verified metadata,
// preservation of intentionally discarded classes, or execution authorization.
CK_FS_POLICY_API ckfe_policy_result ckfe_preservation_assess_v1(
    const ckfe_preservation_policy_v1 *policy,
    const ckfe_preservation_inventory_v1 *inventory,
    ckfe_preservation_assessment_v1 *assessment, size_t assessment_size) CK_FS_POLICY_NOEXCEPT;

#ifdef __cplusplus
}
#endif
#undef CK_FS_POLICY_NOEXCEPT
#endif
