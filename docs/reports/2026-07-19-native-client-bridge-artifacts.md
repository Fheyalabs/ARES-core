# Native Client Bridge Artifact Evidence

Date: 2026-07-19

## Scope

This report records release-staging evidence for the ARES-core bridge
artifacts introduced by the native client artifact plan. It does not certify
the separately-owned Fheya Rust privacy core, a combined Fheya release
manifest, a Maven publication, or an Android device build.

The staged Apple XCFramework contains the canonical bridge source:

- `pkg/ares/crypto/cgo/openfhe_wrapper.{h,cpp}`
- `clients/kotlin/native/jni_openfhe.cpp` remains the Android JNI source

It is built against the pinned OpenFHE source rather than relying on a local
Homebrew installation or an environment-selected source directory.

## Source Validation

Executed from this worktree at ARES-core revision
`f5b403093b3849e240aeb48f8561f940b58a3e22`:

```sh
go test ./clients/native/... -count=1 -v
go vet ./...
go build ./...
git diff --check
```

All commands exited zero. The native test suite covers the required Apple
slices and Android ABIs using a mocked toolchain, pin validation, fail-closed
missing-toolchain paths, canonical bridge-source ownership, and immutable
Swift release-manifest constraints. It is not a substitute for a native
compiler build.

## Real Apple Build

The following serialized build was executed with bounded compiler
parallelism on an Apple Silicon Mac:

```sh
PATH=/opt/homebrew/bin:$PATH \
ARES_NATIVE_BUILD_JOBS=2 \
./clients/native/build-apple-xcframework.sh \
  /Volumes/Hardik_external_T7/ares-release-artifacts/apple-20260719-bridge
```

It completed all required slices:

- `ios-arm64`
- `ios-arm64-simulator`
- `macos-arm64`

Resulting artifact:

```text
/Volumes/Hardik_external_T7/ares-release-artifacts/apple-20260719-bridge/AresPrivacyCore-v1.5.1-apple.xcframework.zip
SHA-256: 944ff03fa07bd44564ab459ba0b0ebc6664b48f4173fa48653e8ce6e14f0521e
```

The generated staging manifest records the pinned OpenFHE tag `v1.5.1` and
source commit `1306d14f8c26bb6150d3e6ad54f28dfe1007689e`, the ARES-core
revision above, the artifact hash, and hashes for the accompanying SBOM and
provenance documents. The archive contains `libAresPrivacyCore.a`,
`openfhe_wrapper.h`, and `module.modulemap` for every required slice.

## Clean Consumer Check

To test the release-only Swift manifest without changing the development
manifest, the source targets and `Package.release.swift` were copied to a
disposable directory on the external volume. The staged XCFramework was
unzipped into `Artifacts/AresPrivacyCore.xcframework`, then the following
commands were run:

```sh
swift package dump-package
swift build -c release --target AresClientFHE
```

`AresClientFHE` completed successfully against the staged macOS binary
target. The only compiler diagnostic is an existing Swift deprecation in
`FHEEnvironment.swift` for `String(cString:)`; it does not alter the native
artifact result and should be cleaned up before the final client release.

## Unverified Boundaries

- This host has neither `ANDROID_NDK_HOME`/`ANDROID_NDK_ROOT` nor `JAVA_HOME`
  configured. `build-android-aar.sh` correctly refuses to run, so no Android
  AAR is claimed as real-build verified.
- The staged Apple artifact is unsigned because
  `ARES_NATIVE_APPLE_CODESIGN_IDENTITY` was intentionally unset. Its hash and
  provenance are recorded, but final distribution must add release signing.
- Fheya's final release assembler must still stage this artifact with the
  Rust privacy-core bindings and invoke the Fheya `release-artifact-gate` on
  the combined cache. This ARES-core work only establishes a real, immutable
  Apple input for that later gate.
