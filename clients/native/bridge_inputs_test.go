package native_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeBridgeProjectsUseCanonicalSources(t *testing.T) {
	for _, path := range []string{
		"clients/native/bridge/apple/CMakeLists.txt",
		"clients/native/bridge/android/CMakeLists.txt",
	} {
		raw, err := os.ReadFile(filepath.Join(repoRoot(t), path))
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if !strings.Contains(string(raw), "pkg/ares/crypto/cgo/openfhe_wrapper.cpp") {
			t.Fatalf("%s does not reference the canonical OpenFHE bridge source", path)
		}
	}
}
