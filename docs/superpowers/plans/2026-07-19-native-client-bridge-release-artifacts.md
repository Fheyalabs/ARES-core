# Native Client Bridge Release Artifacts Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (\`- [ ]\`) syntax for tracking.

**Goal:** Produce immutable Apple and Android artifacts that package ARES-core's canonical OpenFHE bridge, rather than raw OpenFHE libraries that a consumer must rebuild locally.

**Architecture:** The existing pinned OpenFHE builds remain the source of native cryptography. Each platform builds the same tracked C bridge against its freshly-built OpenFHE install: Apple combines the bridge object and OpenFHE static components into AresPrivacyCore.xcframework; Android builds libares_fhe_jni.so against the per-ABI OpenFHE shared objects and puts all four libraries in one AAR. A release-only Swift package manifest consumes the Apple binary target without an environment variable or local toolchain path. Fheya's final release assembler remains responsible for combining these ARES artifacts with separately-owned Rust privacy-core evidence.

**Tech Stack:** Bash, CMake, C++17, Xcode/XCFramework, Android NDK, JNI, Swift Package Manager, Go native-script tests.

## Global Constraints

- OpenFHE is pinned exclusively by clients/native/openfhe.pin.json: v1.5.1 and its exact commit.
- Native builds are serial and default to ARES_NATIVE_BUILD_JOBS=2. Build output is outside the repository.
- Required Apple slices: ios-arm64, ios-arm64-simulator, macos-arm64. Required Android ABIs: arm64-v8a, x86_64.
- Bridge source is canonical: pkg/ares/crypto/cgo/openfhe_wrapper.{h,cpp} and clients/kotlin/native/jni_openfhe.cpp. No copied crypto implementation.
- Production artifacts may not use /usr/local, /opt/homebrew, ARES_OPENFHE, FHEYA_ARES_CORE_SWIFT_PATH, or ARES_CORE_KOTLIN_PATH.
- Missing bridge source, native output, required architecture, JNI headers, or an in-repository output directory fails closed.
- This plan does not claim to produce Fheya's Rust privacy-core or complete its combined release manifest.

## File Structure

- clients/native/bridge/apple/CMakeLists.txt: builds the C wrapper static archive against an installed Apple OpenFHE slice.
- clients/native/bridge/android/CMakeLists.txt: builds the canonical JNI and C wrapper into libares_fhe_jni.so.
- clients/native/lib/common.sh: canonical-source and C module-header staging helpers.
- clients/native/build-apple-xcframework.sh: creates a bridge-inclusive Apple XCFramework.
- clients/native/build-android-aar.sh: creates a bridge-inclusive Android AAR.
- clients/swift/Package.release.swift: immutable binary-target SwiftPM manifest.
- clients/native/*_test.go: mocked-toolchain contract tests.
- clients/native/README.md and docs/reports/2026-07-19-native-client-bridge-artifacts.md: consumer and evidence documentation.

### Task 1: Canonical Bridge Build Inputs

**Files:**
- Create: clients/native/bridge/apple/CMakeLists.txt
- Create: clients/native/bridge/android/CMakeLists.txt
- Modify: clients/native/lib/common.sh
- Test: clients/native/bridge_inputs_test.go

**Consumes:** an installed OpenFHE prefix containing include/openfhe and its platform libraries.

**Produces:** CMake targets ares_privacy_core and ares_fhe_jni; shell helpers bridge_source_path, bridge_header_path, and stage_copenfhe_headers DEST.

- [ ] **Step 1: Write a failing source-contract test**

~~~
func TestNativeBridgeProjectsUseCanonicalSources(t *testing.T) {
    for _, file := range []string{
        "clients/native/bridge/apple/CMakeLists.txt",
        "clients/native/bridge/android/CMakeLists.txt",
    } {
        raw, err := os.ReadFile(filepath.Join(repoRoot(t), file))
        if err != nil { t.Fatalf("read %s: %v", file, err) }
        requireContains(t, string(raw), "pkg/ares/crypto/cgo/openfhe_wrapper.cpp")
    }
}
~~~

- [ ] **Step 2: Run RED**

Run: go test ./clients/native -run TestNativeBridgeProjectsUseCanonicalSources -count=1

Expected: FAIL because the bridge CMake projects do not exist.

- [ ] **Step 3: Add minimal CMake and source helpers**

The Apple project must create a static ares_privacy_core target whose source is the ARES_WRAPPER_SOURCE CMake variable, with the OPENFHE_PREFIX include directory and cxx_std_17. The Android project must create shared ares_fhe_jni from ARES_JNI_SOURCE and ARES_WRAPPER_SOURCE, with OPENFHE_PREFIX/lib as link directory and OPENFHEpke, OPENFHEbinfhe, and OPENFHEcore as link libraries.

stage_copenfhe_headers must copy only openfhe_wrapper.h and a module.modulemap declaring module COpenFHEBridge into a caller-owned output directory.

- [ ] **Step 4: Run GREEN**

Run: go test ./clients/native -run TestNativeBridgeProjectsUseCanonicalSources -count=1

Expected: PASS.

- [ ] **Step 5: Commit**

~~~
git add clients/native/bridge clients/native/lib/common.sh clients/native/bridge_inputs_test.go
git commit -m "feat(native): add canonical bridge build inputs"
~~~

### Task 2: Apple Bridge XCFramework

**Files:**
- Modify: clients/native/build-apple-xcframework.sh
- Modify: clients/native/build_apple_xcframework_test.go
- Modify: clients/native/testutil_test.go

**Consumes:** Task 1 static target and all three installed Apple OpenFHE slices.

**Produces:** AresPrivacyCore-v1.5.1-apple.xcframework.zip. Every slice exports libAresPrivacyCore.a and headers/module.modulemap for module COpenFHEBridge.

- [ ] **Step 1: Write failing archive assertions**

~~~
func TestAppleXCFrameworkStagesCanonicalBridgeModule(t *testing.T) {
    // Test-mode fake source and mocked toolchains must yield a zip with:
    // COpenFHEBridge headers/module.modulemap and libAresPrivacyCore.a.
    // Assert all ios-arm64, ios-arm64-simulator, and macos-arm64 slices.
}
~~~

- [ ] **Step 2: Run RED**

Run: go test ./clients/native -run TestAppleXCFrameworkStagesCanonicalBridgeModule -count=1

Expected: FAIL because the existing archive is raw OpenFHE only.

- [ ] **Step 3: Build bridge after each OpenFHE slice**

After build_openfhe_slice, configure the Apple bridge project with the same platform toolchain, installed OpenFHE prefix, and canonical wrapper path. Combine libares_privacy_core.a with the three OpenFHE static libraries using libtool. Pass stage_copenfhe_headers output to xcodebuild -create-xcframework. Publish only AresPrivacyCore-v1.5.1-apple.xcframework.zip; its manifest retains artifact_kind apple_xcframework and records all required slices, the ARES-core commit, and OpenFHE pin.

- [ ] **Step 4: Run GREEN**

Run: go test ./clients/native -run TestAppleXCFramework -count=1

Expected: PASS including old missing-toolchain, pin-mismatch, and missing-slice checks.

- [ ] **Step 5: Commit**

~~~
git add clients/native/build-apple-xcframework.sh clients/native/build_apple_xcframework_test.go clients/native/testutil_test.go
git commit -m "feat(native): stage Apple ARES bridge framework"
~~~

### Task 3: Android JNI AAR

**Files:**
- Modify: clients/native/build-android-aar.sh
- Modify: clients/native/build_android_aar_test.go
- Modify: clients/native/testutil_test.go

**Consumes:** Task 1 JNI target and each installed Android OpenFHE ABI.

**Produces:** AresPrivacyCore-v1.5.1-android.aar with libares_fhe_jni.so, libOPENFHEcore.so, libOPENFHEpke.so, and libOPENFHEbinfhe.so under each required jni ABI directory.

- [ ] **Step 1: Write a failing JNI archive test**

~~~
func TestAndroidAARStagesJNIAlongsideOpenFHE(t *testing.T) {
    // Every required ABI must contain libares_fhe_jni.so plus all three
    // pinned OpenFHE shared libraries.
}
~~~

- [ ] **Step 2: Run RED**

Run: go test ./clients/native -run TestAndroidAARStagesJNIAlongsideOpenFHE -count=1

Expected: FAIL because the current AAR contains only raw OpenFHE shared libraries.

- [ ] **Step 3: Build and stage JNI per ABI**

After each OpenFHE install, configure the Android bridge project using that NDK toolchain and OPENFHE_PREFIX. Require JDK JNI include headers and libares_fhe_jni.so. Set its Android runpath to $ORIGIN and copy it with the three OpenFHE shared libraries into jni/<abi>. Publish AresPrivacyCore-v1.5.1-android.aar and preserve fail-closed NDK/ABI behavior.

- [ ] **Step 4: Run GREEN**

Run: go test ./clients/native -run TestAndroidAAR -count=1

Expected: PASS including existing NDK and missing-ABI checks.

- [ ] **Step 5: Commit**

~~~
git add clients/native/build-android-aar.sh clients/native/build_android_aar_test.go clients/native/testutil_test.go
git commit -m "feat(native): stage Android ARES JNI artifact"
~~~

### Task 4: Immutable Swift Consumer Manifest

**Files:**
- Create: clients/swift/Package.release.swift
- Create: clients/native/release_swift_manifest_test.go
- Modify: clients/native/README.md

**Consumes:** Task 2 staged artifact layout.

**Produces:** a SwiftPM manifest that exposes AresClient, AresTransport, and AresClientFHE while importing COpenFHEBridge from Artifacts/AresPrivacyCore.xcframework.

- [ ] **Step 1: Write a failing manifest contract test**

~~~
func TestReleaseSwiftManifestUsesOnlyStagedBridgeBinary(t *testing.T) {
    raw, err := os.ReadFile(filepath.Join(repoRoot(t), "clients/swift/Package.release.swift"))
    if err != nil { t.Fatal(err) }
    requireContains(t, string(raw), ".binaryTarget(name: \"COpenFHEBridge\"")
    requireNotContains(t, string(raw), "ProcessInfo.processInfo.environment")
    requireNotContains(t, string(raw), "/usr/local")
    requireNotContains(t, string(raw), "/opt/homebrew")
}
~~~

- [ ] **Step 2: Run RED**

Run: go test ./clients/native -run TestReleaseSwiftManifestUsesOnlyStagedBridgeBinary -count=1

Expected: FAIL because Package.release.swift does not exist.

- [ ] **Step 3: Add release-only Swift manifest**

Declare a binaryTarget named COpenFHEBridge at Artifacts/AresPrivacyCore.xcframework. Declare source targets AresClient, AresTransport, and AresClientFHE; AresClientFHE depends on COpenFHEBridge and links c++. Do not alter development Package.swift or introduce an environment switch.

- [ ] **Step 4: Run GREEN and document staging**

Run: go test ./clients/native -run TestReleaseSwiftManifestUsesOnlyStagedBridgeBinary -count=1

Expected: PASS.

- [ ] **Step 5: Commit**

~~~
git add clients/swift/Package.release.swift clients/native/release_swift_manifest_test.go clients/native/README.md
git commit -m "feat(swift): add immutable native release manifest"
~~~

### Task 5: Evidence and Real Build

**Files:**
- Modify: clients/native/README.md
- Create: docs/reports/2026-07-19-native-client-bridge-artifacts.md

**Consumes:** Tasks 1-4.

**Produces:** source-test evidence and either a completed serialized real Apple artifact build or an exact recorded toolchain/link failure.

- [ ] **Step 1: Run source validation**

Run: go test ./clients/native/... -count=1 -v && go vet ./... && go build ./... && git diff --check

Expected: PASS.

- [ ] **Step 2: Run the serialized real Apple build**

Run: ARES_NATIVE_BUILD_JOBS=2 clients/native/build-apple-xcframework.sh /Volumes/Hardik_external_T7/ares-release-artifacts/apple

Expected: a three-slice bridge XCFramework plus hash, SBOM, and provenance, or a nonzero failure with the exact command recorded. Mocked tests are never native-release evidence.

- [ ] **Step 3: Record evidence and commit**

~~~
git add clients/native/README.md docs/reports/2026-07-19-native-client-bridge-artifacts.md
git commit -m "docs(native): record bridge artifact evidence"
~~~

## Self-Review

- Canonical C/C++ sources are compiled directly; nothing reimplements FHE in Swift or Kotlin.
- All platform-specific functionality has a red-first mocked test and an explicit real-build evidence boundary.
- The result provides platform-consumable bridge artifacts, but deliberately does not pretend to complete Fheya's separate Rust privacy-core provenance or the final release-artifact gate.

