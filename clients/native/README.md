# clients/native

Native client artifact staging layer for the v0.9.15 release line: builds
and stages the pinned OpenFHE 1.5.1 **and ARES-core's canonical C/JNI bridge**
from clean, pinned source, cross-compiled per platform/ABI.

The Apple artifact is `AresPrivacyCore.xcframework`: a static library that
combines the canonical `openfhe_wrapper.cpp` with OpenFHE and exports the
`COpenFHEBridge` C module. The Android artifact is an AAR containing
`libares_fhe_jni.so` beside the three OpenFHE shared libraries for every
required ABI. Both use the same tracked bridge source already exercised by
the Go, Swift, and Kotlin development clients; neither duplicates FHE logic.

`clients/swift/Package.release.swift` is the immutable consumer manifest for
a release staging directory. It declares a `COpenFHEBridge` binary target at
`Artifacts/AresPrivacyCore.xcframework`; it contains no local Homebrew path,
environment switch, or workstation dependency. The tracked `Package.swift`
remains the development manifest and is intentionally not a release input.

**Scope boundary:** the scripts do not publish a Maven coordinate, alter a
consumer Gradle dependency, or build Fheya's independently-owned Rust privacy
core. Fheya's release assembler must combine these ARES-core artifacts with
that separate binding and provenance evidence before invoking its complete
release-artifact gate.

## Pins

- `openfhe.pin.json` — `openfhe_version` (git tag), `openfhe_source_url`,
  and `openfhe_source_commit` (the exact commit that tag must resolve to).
  Verified live against `https://api.github.com/repos/openfheorg/openfhe-development/git/refs/tags/v1.5.1`
  when this pin was written.
- `android-ndk.pin.json` — `android_ndk_min_major_version`, the minimum
  Android NDK major version `build-android-aar.sh` accepts.

Both files are the sole tracked source of truth for what is releasable.
Neither script accepts an ordinary environment variable to redirect them —
that would reopen exactly the bypass `clients/swift/FheyaClient/Package.swift`'s
`FHEYA_ARES_CORE_SWIFT_PATH` local-development escape hatch represents for a
release build. The only override is `ARES_NATIVE_TEST_MODE=1` plus an
explicitly-named `ARES_NATIVE_TEST_*` variable, gated so it can never
activate by accident; see "Testing" below.

## Usage

```
clients/native/build-apple-xcframework.sh OUTPUT_DIR
clients/native/build-android-aar.sh OUTPUT_DIR
```

`OUTPUT_DIR` is a required, explicit argument. There is no default, and a
path that resolves inside this repository's working tree is rejected —
native build output (source clones, object files, the staged artifacts
themselves) must never be committed, and giving it nowhere accidental to
land is the enforcement mechanism, not a policy note. Point it at somewhere
like `/Volumes/<external-disk>/native-staging` locally, or `${RUNNER_TEMP}`
in CI (see `.github/workflows/release-clients.yml`).

Each script writes, into `OUTPUT_DIR`:

- the artifact itself (`AresPrivacyCore-<version>-apple.xcframework.zip` or
  `AresPrivacyCore-<version>-android.aar`);
- `*.sbom.json` — a minimal CycloneDX-shaped SBOM naming the embedded
  OpenFHE version/commit and ARES bridge artifact;
- `*.provenance.json` — a minimal SLSA-provenance-shaped statement binding
  the artifact's SHA-256 to its exact source commit and the ares-core
  revision that triggered the build;
- `*.staging-manifest.json` — see schema below.

A `.work/` subdirectory under `OUTPUT_DIR` holds the OpenFHE source clone
and per-platform/per-ABI build directories; each build directory is removed
immediately after that slice installs successfully (see "Disk usage"
below), so it does not need to be cleaned up separately, but nothing
prevents deleting `OUTPUT_DIR/.work` once staging succeeds.

## Fail-closed guarantees

Both scripts exit nonzero and produce **no** artifact/manifest, rather than
a partial or best-effort one, when:

- any required toolchain command is missing (`git`, `jq`, `cmake`, plus
  `xcodebuild`/`libtool`/`zip` for Apple; `cmake` plus the NDK for Android);
- the installed Xcode version does not report a parsable `Xcode N.M` string;
- `ANDROID_NDK_HOME` (or `ANDROID_NDK_ROOT`) is unset, does not exist, has
  no `build/cmake/android.toolchain.cmake`, has no `source.properties`, or
  reports a major version below `android-ndk.pin.json`'s pinned minimum;
- the cloned OpenFHE tag's actual `HEAD` commit does not exactly equal the
  pinned `openfhe_source_commit` — a moved or re-pointed upstream tag is
  caught, not trusted;
- any required platform slice (Apple: `ios-arm64`, `ios-arm64-simulator`,
  `macos-arm64`) or ABI (Android: `arm64-v8a`, `x86_64`) fails to build or
  produce its bridge and OpenFHE libraries;
- `JAVA_HOME` is absent or does not provide both `include/jni.h` and a
  supported `jni_md.h` platform header for the Android JNI build;
- the output directory argument is missing, or resolves inside this
  repository.

Optional/extra Android ABIs (`armeabi-v7a`, `x86` via
`ARES_NATIVE_ANDROID_EXTRA_ABIS`) are attempted but are not part of the
fail-closed required set.

Apple XCFramework signing (`ARES_NATIVE_APPLE_CODESIGN_IDENTITY`) is
best-effort: an unset identity stages an unsigned, hash-verified artifact
and logs that explicitly, rather than failing the whole build, since a
local/CI staging run will not usually have a release signing identity
available. The SHA-256 in the staging manifest is the primary integrity
check regardless of signing state.

## Staging manifest schema

```json
{
  "schema_version": 1,
  "artifact_kind": "apple_xcframework | android_aar",
  "artifact_path": "...",
  "artifact_sha256": "...",
  "openfhe_version": "v1.5.1",
  "openfhe_source_commit": "...",
  "ares_core_source_revision": "...",
  "target_architectures": ["..."],
  "sbom_path": "...",
  "sbom_sha256": "...",
  "provenance_path": "...",
  "provenance_sha256": "...",
  "generated_at": "..."
}
```

This is deliberately shaped to compose with the sibling Fheya-server
release-audit gate's schema
(`internal/releaseaudit.NativeArtifact{Path,SHA256,BuiltFromRevision,AresCoreRevision}`
plus `HashedFile{Path,SHA256}` for SBOM/provenance, see
`ARES/internal/releaseaudit/README.md` in that repo's release-gate
worktrees) — `ares_core_source_revision` here is what a consuming manifest
would record as `built_from_revision`/`ares_core_revision`. Wiring this
gate's output into that verifier is future integration work; this repo does
not depend on or import anything from it.

## Disk usage and RSS

These are from-scratch native builds of a template-heavy C++ lattice-crypto
library, not lightweight scripting. Budget accordingly before running a
real (non-mocked) build:

- **Per-slice/per-ABI build**: OpenFHE's own build system reports comparable
  full from-source builds taking on the order of several minutes to tens of
  minutes per target on a modern multi-core machine, with compiler RSS in
  the low single-digit GB range per parallel job (some translation units in
  `PALISADE`/`OpenFHE`'s core and `pke` libraries are large template
  instantiations). `ARES_NATIVE_BUILD_JOBS` (default `2`) bounds
  parallelism, and therefore peak RSS, deliberately rather than defaulting
  to "all cores" — raise it only on a machine with enough free RAM per job
  (roughly 2-3 GiB free per job is a reasonable starting budget; measure on
  your own machine before raising it for a real release build).
- **Disk**: a single platform/ABI's build directory (object files) has been
  observed in the low-single-digit-GB range for OpenFHE; both scripts
  delete each build directory immediately after that slice's `cmake
  --install` succeeds, so peak disk usage stays close to one build
  directory's worth plus the (much smaller, header+library only) install
  directories already completed, rather than growing linearly with the
  full platform/ABI list. The final staged artifacts themselves (combined
  static libs in an xcframework, or per-ABI shared libs in an aar) are
  small by comparison (tens of MB).
- **Serialization**: both scripts build platforms/ABIs strictly one at a
  time (a plain sequential loop, never backgrounded) — this is the "native
  builds are serialized" requirement, distinct from
  `ARES_NATIVE_BUILD_JOBS` (which only bounds *compiler* parallelism
  *within* one slice's build). The release workflow additionally serializes
  the Apple and Android jobs against each other (see
  `.github/workflows/release-clients.yml`) even though they run on
  independent macOS/Ubuntu runners and could technically overlap.
- Always point `OUTPUT_DIR` at a volume with enough free space for at least
  one platform/ABI's peak build directory plus the source clone (OpenFHE's
  source tree itself is on the order of a few hundred MB) — never the
  system/boot volume if that volume is otherwise low on space.

## Testing

`clients/native/*_test.go` (package `native_test`, run via `go test
./clients/native/...`) drive both scripts as real subprocesses against a
fully controlled `PATH` (real `git`/`jq`/`zip`/coreutils, plus mocked
`cmake`/`xcodebuild`/`libtool` that fake a successful or selectively-failing
build without ever compiling anything) and a real, tiny local git
repository standing in for the OpenFHE source (so `clone_pinned_openfhe`'s
`git clone` + commit-verification logic is exercised for real, just against
a fast local repo instead of the network). This is what
`ARES_NATIVE_TEST_MODE=1` plus `ARES_NATIVE_TEST_OPENFHE_SOURCE_URL` /
`ARES_NATIVE_TEST_PIN_FILE` / `ARES_NATIVE_TEST_NDK_PIN_FILE` exist for —
they are read only when `ARES_NATIVE_TEST_MODE=1` is also set, so they can
never activate against a real release invocation by accident.

Run the tests:

```
go test ./clients/native/... -v -count=1
```

These tests never invoke a real toolchain build (no real OpenFHE compile
happens), so they run in seconds. Run a real, non-mocked build only when
the real toolchains (Xcode, Android NDK, cmake) are already installed and
the target volume has enough free space per the disk guidance above.
