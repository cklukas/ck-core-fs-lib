---
title: ck-core-fs-lib
description: Headless, cross-platform filesystem operations with a stable C ABI.
layout: home
hero:
  name: ck-core-fs-lib
  text: Safe filesystem operations for native clients
  tagline: >
    A headless, cross-platform engine for native file identity, byte-native
    names, journaled mutation, recovery evidence and stable C integration.
  actions:
    - text: Explore the architecture
      link: architecture.md
      theme: brand
    - text: Read the C API
      link: c-api.md
    - text: Build the library
      link: building.md
features:
  - icon: ":shield:"
    title: Safety-first operations
    details: Held handles, explicit identity, journaled mutation and recovery evidence keep filesystem changes inspectable.
    link: safety.md
  - icon: ":link:"
    title: Stable native interfaces
    details: C++ and exception-free opaque-handle C APIs expose the same headless engine without UI dependencies.
    link: integration.md
  - icon: ":desktop_computer:"
    title: CK Core CDE
    details: Explore the maintained desktop environment that can consume the filesystem library through its stable C boundary.
    link: https://cklukas.github.io/ck-core-cde/
  - icon: ":toolbox:"
    title: CK Core Apps
    details: Explore native desktop applications built for the maintained CDE and Motif stack.
    link: https://cklukas.github.io/ck-core-apps/
  - icon: "🏗️"
    title: CK Core Motif
    details: Explore the maintained native Xt toolkit used by CK Core desktop clients.
    link: https://cklukas.github.io/ck-core-motif/
---

# ck-core-fs-lib

`ck-core-fs-lib` is the headless filesystem engine shared by the ckUtilities
ckVision frontend, CDE, and future clients. It owns native file identity,
byte-native names, safe directory access, journaled mutation, recovery
evidence, and cross-platform path handling. It does not own a UI, terminal,
event loop, or frontend policy.

The project exposes two layers over the same implementation:

- a C++ target for native clients that already use the backend types; and
- an exception-free opaque-handle C ABI for CDE, other languages, and stable
  frontend adapters.

The C ABI includes held-handle inspection, journaled regular-file jobs,
native reviewed-tree workers, action jobs, and durable session contracts.
Read [native contracts](native-contracts.md) for implemented scopes, lifetime
rules and explicit provider limits. See the revision-specific validation
record before enabling a capability in a frontend.

See [architecture](architecture.md) for the ownership boundary, [safety](safety.md)
for the non-negotiable filesystem rules, and [the C API](c-api.md) for the
public integration surface.
