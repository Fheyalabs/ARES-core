#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"   # clients/kotlin
BUILD="$ROOT/native/build"
OUT="$ROOT/ares-client-fhe/build/native"
cmake -S "$ROOT/native" -B "$BUILD" -DCMAKE_BUILD_TYPE=Release >/dev/null
cmake --build "$BUILD" --config Release >/dev/null
mkdir -p "$OUT"
# macOS produces libares_fhe_jni.dylib; copy to a stable java.library.path dir.
cp "$BUILD"/libares_fhe_jni.* "$OUT"/ 2>/dev/null || cp "$BUILD"/*/libares_fhe_jni.* "$OUT"/
echo "native lib in: $OUT"
