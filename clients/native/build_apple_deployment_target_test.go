package native_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAppleXCFrameworkFailsClosedWithoutSwVers(t *testing.T) {
	path := newMockPath(t, map[string]string{
		"cmake":      mockCMakeScript,
		"xcodebuild": mockXcodebuildScript,
		"libtool":    mockLibtoolScript,
		"otool":      mockOtoolScript,
	})
	out := t.TempDir()
	res := runScript(t, appleScriptPath(t), []string{out}, path, nil)
	if res.exitCode == 0 {
		t.Fatalf("expected nonzero exit, got 0")
	}
	if !strings.Contains(res.stderr, "sw_vers") {
		t.Fatalf("expected an sw_vers-related failure, got stderr=%s", res.stderr)
	}
}

func TestAppleXCFrameworkFailsClosedWithoutOtool(t *testing.T) {
	path := newMockPath(t, map[string]string{
		"cmake":      mockCMakeScript,
		"xcodebuild": mockXcodebuildScript,
		"libtool":    mockLibtoolScript,
		"sw_vers":    mockSwVersScript,
	})
	out := t.TempDir()
	res := runScript(t, appleScriptPath(t), []string{out}, path, nil)
	if res.exitCode == 0 {
		t.Fatalf("expected nonzero exit, got 0")
	}
	if !strings.Contains(res.stderr, "otool") {
		t.Fatalf("expected an otool-related failure, got stderr=%s", res.stderr)
	}
}

func TestAppleXCFrameworkFailsClosedOnMissingDeploymentTargetPin(t *testing.T) {
	url, commit := newFakeOpenFHETagRepo(t, applePinnedVersion)
	pin := writeTestPin(t, applePinnedVersion, url, commit)
	out := t.TempDir()
	res := runScript(t, appleScriptPath(t), []string{out}, fullApplePath(t), map[string]string{
		"ARES_NATIVE_TEST_MODE":               "1",
		"ARES_NATIVE_TEST_OPENFHE_SOURCE_URL": url,
		"ARES_NATIVE_TEST_PIN_FILE":           pin,
		"ARES_NATIVE_TEST_APPLE_DEPLOYMENT_TARGET_PIN_FILE": filepath.Join(t.TempDir(), "does-not-exist.json"),
	})
	if res.exitCode == 0 {
		t.Fatalf("expected nonzero exit, got 0")
	}
	if !strings.Contains(res.stderr, "deployment-target pin file not found") {
		t.Fatalf("expected a missing-pin-file failure, got stderr=%s", res.stderr)
	}
}

func TestAppleXCFrameworkFailsClosedOnMalformedDeploymentTargetPin(t *testing.T) {
	for _, malformed := range []string{"", "14", "abc", "14.x"} {
		t.Run(malformed, func(t *testing.T) {
			url, commit := newFakeOpenFHETagRepo(t, applePinnedVersion)
			pin := writeTestPin(t, applePinnedVersion, url, commit)
			deploymentPin := writeTestAppleDeploymentTargetPin(t, malformed)
			out := t.TempDir()
			res := runScript(t, appleScriptPath(t), []string{out}, fullApplePath(t), map[string]string{
				"ARES_NATIVE_TEST_MODE":               "1",
				"ARES_NATIVE_TEST_OPENFHE_SOURCE_URL": url,
				"ARES_NATIVE_TEST_PIN_FILE":           pin,
				"ARES_NATIVE_TEST_APPLE_DEPLOYMENT_TARGET_PIN_FILE": deploymentPin,
			})
			if res.exitCode == 0 {
				t.Fatalf("expected nonzero exit for malformed target %q, got 0", malformed)
			}
			if !strings.Contains(res.stderr, "macos_minimum_deployment_target") {
				t.Fatalf("expected a macos_minimum_deployment_target-related failure, got stderr=%s", res.stderr)
			}
		})
	}
}

func TestAppleXCFrameworkFailsClosedOnHostNewerDeploymentTarget(t *testing.T) {
	url, commit := newFakeOpenFHETagRepo(t, applePinnedVersion)
	pin := writeTestPin(t, applePinnedVersion, url, commit)
	// Pin a deployment target newer than the (mocked) host's reported
	// macOS version: the host cannot meaningfully build or validate
	// against a target newer than itself.
	deploymentPin := writeTestAppleDeploymentTargetPin(t, "20.0")
	out := t.TempDir()
	res := runScript(t, appleScriptPath(t), []string{out}, fullApplePath(t), map[string]string{
		"ARES_NATIVE_TEST_MODE":               "1",
		"ARES_NATIVE_TEST_OPENFHE_SOURCE_URL": url,
		"ARES_NATIVE_TEST_PIN_FILE":           pin,
		"ARES_NATIVE_TEST_APPLE_DEPLOYMENT_TARGET_PIN_FILE": deploymentPin,
		"MOCK_SW_VERS_PRODUCT_VERSION":                      "15.0",
	})
	if res.exitCode == 0 {
		t.Fatalf("expected nonzero exit, got 0")
	}
	if !strings.Contains(res.stderr, "newer than the host macOS version") {
		t.Fatalf("expected a host-newer rejection, got stderr=%s", res.stderr)
	}
}

func TestAppleXCFrameworkFailsClosedOnRealMachOMismatch(t *testing.T) {
	url, commit := newFakeOpenFHETagRepo(t, applePinnedVersion)
	pin := writeTestPin(t, applePinnedVersion, url, commit)
	out := t.TempDir()
	res := runScript(t, appleScriptPath(t), []string{out}, fullApplePath(t), map[string]string{
		"ARES_NATIVE_TEST_MODE":               "1",
		"ARES_NATIVE_TEST_OPENFHE_SOURCE_URL": url,
		"ARES_NATIVE_TEST_PIN_FILE":           pin,
		// Pin (and mocked host) accept 14.0, but the mocked otool reports
		// that the built library actually links against 15.0 -- exactly
		// the class of real-world drift (a flag that did not propagate to
		// every translation unit) this inspection step exists to catch.
		"MOCK_OTOOL_MINOS": "15.0",
	})
	if res.exitCode == 0 {
		t.Fatalf("expected nonzero exit, got 0")
	}
	if !strings.Contains(res.stderr, "Mach-O deployment target mismatch") {
		t.Fatalf("expected a Mach-O deployment-target mismatch failure, got stderr=%s", res.stderr)
	}
	manifest := filepath.Join(out, "OpenFHE-"+applePinnedVersion+"-apple.staging-manifest.json")
	if _, err := os.Stat(manifest); err == nil {
		t.Fatal("no staging manifest must be produced when real Mach-O inspection finds a mismatch")
	}
}

func TestAppleXCFrameworkPropagatesDeploymentTargetIntoManifest(t *testing.T) {
	url, commit := newFakeOpenFHETagRepo(t, applePinnedVersion)
	pin := writeTestPin(t, applePinnedVersion, url, commit)
	deploymentPin := writeTestAppleDeploymentTargetPin(t, "13.5")
	out := t.TempDir()
	res := runScript(t, appleScriptPath(t), []string{out}, fullApplePath(t), map[string]string{
		"ARES_NATIVE_TEST_MODE":               "1",
		"ARES_NATIVE_TEST_OPENFHE_SOURCE_URL": url,
		"ARES_NATIVE_TEST_PIN_FILE":           pin,
		"ARES_NATIVE_TEST_APPLE_DEPLOYMENT_TARGET_PIN_FILE": deploymentPin,
		"MOCK_OTOOL_MINOS": "13.5",
	})
	if res.exitCode != 0 {
		t.Fatalf("expected success, got exit=%d\nstdout=%s\nstderr=%s", res.exitCode, res.stdout, res.stderr)
	}

	manifestPath := filepath.Join(out, "OpenFHE-"+applePinnedVersion+"-apple.staging-manifest.json")
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("reading manifest: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("manifest is not valid JSON: %v\n%s", err, raw)
	}
	if got := m["apple_macos_deployment_target"]; got != "13.5" {
		t.Fatalf("apple_macos_deployment_target = %v, want 13.5", got)
	}
}
