# Installed library layer regression

This project must be configured separately against a freshly installed SDK.
It links each executable to exactly one exported target. Do not add archive
repetitions, archive groups, whole-archive flags, private build-tree include
paths or copied SDK implementation sources.

```
cmake -S tests/installed_layers -B <consumer-build> \
  -DCMAKE_PREFIX_PATH=<fresh-install-prefix> \
  -DCK_LAYER_FIXTURE_ROOT=<explicit-existing-native-temporary-root>
cmake --build <consumer-build> --parallel 1
ctest --test-dir <consumer-build> --output-on-failure --parallel 1
```

Core exercises portable metadata policy/limits and cleanup observation, a
provider-neutral HeldChild rejection, and injected-session input rejection.
The linked Core archive must not require a concrete platform factory merely
because one of these portable operations is selected. Platform and Native
consume real source metadata; Native additionally produces a bounded two-pass
main-content proof. Linux cases create and publish an anonymous native staging
file, then independently read the published content. C API consumes real file
metadata through the installed shared runtime.

On Linux, generated link maps allow inspection of the actual archive members.
Core must not load Platform or Native. Native's transitive dependencies must be
Platform then Core, once each. No consumer may select two SDK prefixes. The
native staging suite in the provider project must also link and run with its
existing mandatory native/unprivileged/thread-FD controls.

The implementation fix assigns native capture/replay/preservation/copy workers
to Platform with their concrete provider factories. Pure policy, digest,
budget-limit and cleanup primitives stay in Core. The two HeldChild replay
methods and native session-root acquisition helper are split from portable
object implementations. No class/vtable/public-C layout or native validation
contract changes. The relocation preserves actual provider authentication,
Root first-error bridges, explicit closes, and typed unsupported results.

Linux is the qualified native provider for this packet. These portable consumer
sources are not by themselves Windows or Darwin qualification.
