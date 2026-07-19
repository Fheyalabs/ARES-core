#!/usr/bin/env bash
# Builds and stages the pinned OpenFHE Apple XCFramework from clean,
# pinned source. See clients/native/openfhe.pin.json for the exact version
# and source commit, and clients/native/README.md for expected RSS/disk
# usage and the staging-manifest schema.
#
# This script builds ONLY OpenFHE's own native library, cross-compiled for
# each required Apple platform slice, and packages it as a standalone
# .xcframework. It does not touch Package.swift or any ares-core Swift
# target; wiring a consuming binaryTarget to this artifact is separate,
# out-of-scope release-packaging work.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

# Required platform slices. macos-arm64 is the "host test architecture"
# used for local Swift Package tests; ios-arm64 is the device slice;
# ios-arm64-simulator is the Apple Silicon simulator slice. All three are
# required -- a build that produces only some of them fails closed rather
# than shipping an incomplete xcframework.
REQUIRED_PLATFORMS=(ios-arm64 ios-arm64-simulator macos-arm64)

# Native builds are serialized deliberately: this script never launches
# more than one platform slice's cmake configure/build/install at a time,
# and the release workflow never runs this script concurrently with
# build-android-aar.sh. Intra-build compiler parallelism (ARES_NATIVE_BUILD_JOBS)
# is a separate, bounded knob -- see README.md for RSS guidance.
BUILD_JOBS="${ARES_NATIVE_BUILD_JOBS:-2}"

usage() {
  cat >&2 <<'EOF'
Usage: build-apple-xcframework.sh OUTPUT_DIR

Builds the pinned OpenFHE Apple XCFramework (ios-arm64, ios-arm64-simulator,
macos-arm64) from clean, pinned source and stages it, its SBOM, its
provenance statement, and a staging manifest into OUTPUT_DIR.

OUTPUT_DIR is required and must resolve outside this repository's working
tree; there is no default and no path inside the repo is accepted.

Environment:
  ARES_NATIVE_BUILD_JOBS               compiler parallelism per slice (default: 2)
  ARES_NATIVE_APPLE_CODESIGN_IDENTITY  optional codesign identity; unset skips signing
EOF
}

build_openfhe_slice() {
  local src="$1" install_dir="$2" platform="$3"
  local build_dir="${src}-build-${platform}"
  rm -rf "${build_dir}" "${install_dir}"

  local -a cmake_args=(
    -S "${src}" -B "${build_dir}"
    -DCMAKE_INSTALL_PREFIX="${install_dir}"
    -DBUILD_BENCHMARKS=OFF -DBUILD_UNITTESTS=OFF -DBUILD_EXAMPLES=OFF -DBUILD_EXTRAS=OFF
    -DWITH_OPENMP=OFF -DBUILD_SHARED=OFF -DBUILD_STATIC=ON
  )
  case "${platform}" in
    ios-arm64)
      cmake_args+=(-DCMAKE_SYSTEM_NAME=iOS -DCMAKE_OSX_ARCHITECTURES=arm64 -DCMAKE_OSX_SYSROOT=iphoneos -DCMAKE_OSX_DEPLOYMENT_TARGET=17.0)
      ;;
    ios-arm64-simulator)
      cmake_args+=(-DCMAKE_SYSTEM_NAME=iOS -DCMAKE_OSX_ARCHITECTURES=arm64 -DCMAKE_OSX_SYSROOT=iphonesimulator -DCMAKE_OSX_DEPLOYMENT_TARGET=17.0)
      ;;
    macos-arm64)
      cmake_args+=(-DCMAKE_OSX_ARCHITECTURES=arm64 -DCMAKE_OSX_DEPLOYMENT_TARGET=14.0)
      ;;
    *)
      die "unknown apple platform slice: ${platform}"
      ;;
  esac

  log_info "configuring OpenFHE for ${platform}"
  cmake "${cmake_args[@]}" >&2
  log_info "building OpenFHE for ${platform} (jobs=${BUILD_JOBS})"
  cmake --build "${build_dir}" -j"${BUILD_JOBS}" --target install >&2

  [ -d "${install_dir}/lib" ] || die "OpenFHE build for ${platform} produced no install/lib directory: ${install_dir}/lib"

  # Reclaim the build directory (object files; far larger than the
  # installed libs/headers) immediately once install succeeds, so peak
  # disk usage across the whole run stays close to one slice's build
  # directory rather than growing with every additional platform.
  rm -rf "${build_dir}"
}

combine_openfhe_static_libs() {
  local install_dir="$1" combined="$2"
  local -a libs=()
  local component
  for component in OPENFHEcore OPENFHEpke OPENFHEbinfhe; do
    local lib_path="${install_dir}/lib/lib${component}.a"
    [ -f "${lib_path}" ] || die "expected static library missing after build: ${lib_path}"
    libs+=("${lib_path}")
  done
  mkdir -p "$(dirname "${combined}")"
  libtool -static -o "${combined}" "${libs[@]}"
  [ -f "${combined}" ] || die "libtool did not produce combined static library: ${combined}"
}

main() {
  if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    usage
    exit 0
  fi

  require_cmd git
  require_cmd jq
  require_cmd cmake
  require_cmd xcodebuild
  require_cmd libtool
  require_cmd zip

  require_version_output "Xcode" '^Xcode [0-9]+\.' xcodebuild -version >/dev/null

  local output_dir
  output_dir="$(require_untracked_output_dir "${1:-}")"

  local version commit ares_rev
  version="$(read_pin openfhe_version)"
  commit="$(read_pin openfhe_source_commit)"
  ares_rev="$(ares_core_source_revision)"

  local work_dir="${output_dir}/.work/apple-xcframework"
  rm -rf "${work_dir}"
  mkdir -p "${work_dir}"

  local openfhe_src="${work_dir}/openfhe-src"
  clone_pinned_openfhe "${openfhe_src}"

  local -a built_platforms=()
  local -a slice_libs=()
  local headers_dir=""

  local platform
  for platform in "${REQUIRED_PLATFORMS[@]}"; do
    local install_dir="${work_dir}/install/${platform}"
    build_openfhe_slice "${openfhe_src}" "${install_dir}" "${platform}"
    local combined="${work_dir}/combined/${platform}/libOpenFHE.a"
    combine_openfhe_static_libs "${install_dir}" "${combined}"
    slice_libs+=("${combined}")
    built_platforms+=("${platform}")
    headers_dir="${install_dir}/include/openfhe"
  done

  require_all_present "apple xcframework platform slices" "${REQUIRED_PLATFORMS[@]}" -- "${built_platforms[@]}"
  [ -d "${headers_dir}" ] || die "OpenFHE public headers not found after build: ${headers_dir}"

  local xcframework_dir="${work_dir}/OpenFHE.xcframework"
  rm -rf "${xcframework_dir}"
  local -a xcodebuild_args=(-create-xcframework)
  local lib
  for lib in "${slice_libs[@]}"; do
    xcodebuild_args+=(-library "${lib}" -headers "${headers_dir}")
  done
  xcodebuild_args+=(-output "${xcframework_dir}")

  log_info "creating xcframework from ${#slice_libs[@]} slice(s)"
  xcodebuild "${xcodebuild_args[@]}" >&2
  [ -d "${xcframework_dir}" ] || die "xcodebuild did not produce ${xcframework_dir}"

  if [ -n "${ARES_NATIVE_APPLE_CODESIGN_IDENTITY:-}" ]; then
    require_cmd codesign
    log_info "codesigning xcframework"
    codesign --force --deep --sign "${ARES_NATIVE_APPLE_CODESIGN_IDENTITY}" "${xcframework_dir}" >&2
  else
    log_info "ARES_NATIVE_APPLE_CODESIGN_IDENTITY not set; staging unsigned (SHA-256 is the primary integrity check; record this as provenance-pinned but not code-signed)"
  fi

  local artifact_zip="${output_dir}/OpenFHE-${version}-apple.xcframework.zip"
  rm -f "${artifact_zip}"
  ( cd "${work_dir}" && zip -r -q "${artifact_zip}" "$(basename "${xcframework_dir}")" )

  local artifact_sha256
  artifact_sha256="$(sha256_of "${artifact_zip}")"

  local sbom_path="${output_dir}/OpenFHE-${version}-apple.sbom.json"
  local provenance_path="${output_dir}/OpenFHE-${version}-apple.provenance.json"
  write_sbom "${sbom_path}" "OpenFHE" "${version}" "${commit}"
  write_provenance "${provenance_path}" "$(basename "${artifact_zip}")" "${artifact_sha256}" \
    "${ares_rev}" "${commit}" "ares-core/clients/native/build-apple-xcframework.sh"

  local manifest_path="${output_dir}/OpenFHE-${version}-apple.staging-manifest.json"
  emit_native_manifest "${manifest_path}" "apple_xcframework" "${artifact_zip}" "${artifact_sha256}" \
    "${version}" "${commit}" "${ares_rev}" \
    "${sbom_path}" "${provenance_path}" \
    "${REQUIRED_PLATFORMS[@]}"

  log_info "staged artifact:  ${artifact_zip}"
  log_info "staged sbom:      ${sbom_path}"
  log_info "staged provenance: ${provenance_path}"
  log_info "staged manifest:  ${manifest_path}"
}

main "$@"
