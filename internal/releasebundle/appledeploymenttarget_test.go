package releasebundle_test

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Fheyalabs/ares-core/internal/releasebundle"
	"github.com/Fheyalabs/ares-core/internal/releasebundle/releasebundletest"
)

func TestAssembleRecordsAppleDeploymentTargetInReleaseCacheManifest(t *testing.T) {
	bundleDir, repoRoot := releasebundletest.NewBundle(t, releasebundletest.Opts{})

	m, err := releasebundle.Assemble(bundleDir, repoRoot)
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	if m.Apple.AppleMACOSDeploymentTarget != releasebundletest.AppleMACOSDeploymentTarget {
		t.Fatalf("Apple.AppleMACOSDeploymentTarget = %q, want %q", m.Apple.AppleMACOSDeploymentTarget, releasebundletest.AppleMACOSDeploymentTarget)
	}
	if m.Android.AppleMACOSDeploymentTarget != "" {
		t.Fatalf("Android.AppleMACOSDeploymentTarget = %q, want empty", m.Android.AppleMACOSDeploymentTarget)
	}
}

func TestAssembleRejectsMissingAppleDeploymentTarget(t *testing.T) {
	// Opts always writes some value into the field (an empty override
	// falls back to NewBundle's default), so overwrite the staged
	// manifest directly to exercise a genuinely absent field -- the same
	// class of staging bug this check exists to catch.
	bundleDir, repoRoot := releasebundletest.NewBundle(t, releasebundletest.Opts{})
	overwriteAppleManifestField(t, bundleDir, "apple_macos_deployment_target", "")

	_, err := releasebundle.Assemble(bundleDir, repoRoot)
	if err == nil {
		t.Fatal("expected Assemble to fail on a missing apple_macos_deployment_target, got nil error")
	}
	if !strings.Contains(err.Error(), "apple_macos_deployment_target") {
		t.Errorf("error does not mention apple_macos_deployment_target: %v", err)
	}
}

func TestAssembleRejectsMalformedAppleDeploymentTarget(t *testing.T) {
	for _, malformed := range []string{"14", "abc", "14.x", "14.0.1.2", ""} {
		t.Run(malformed, func(t *testing.T) {
			bundleDir, repoRoot := releasebundletest.NewBundle(t, releasebundletest.Opts{})
			overwriteAppleManifestField(t, bundleDir, "apple_macos_deployment_target", malformed)

			_, err := releasebundle.Assemble(bundleDir, repoRoot)
			if err == nil {
				t.Fatalf("expected Assemble to fail on malformed apple_macos_deployment_target %q, got nil error", malformed)
			}
		})
	}
}

func TestAssembleRejectsAppleDeploymentTargetNewerThanDeclaredPin(t *testing.T) {
	// releasebundletest's fixture repo declares 14.0; recording 15.0 in the
	// staged manifest claims a newer minimum than what the repo currently
	// declares as supported -- exactly the "not a portable release
	// candidate" case this check exists to catch.
	bundleDir, repoRoot := releasebundletest.NewBundle(t, releasebundletest.Opts{
		AppleMACOSDeploymentTargetOverride: "15.0",
	})

	_, err := releasebundle.Assemble(bundleDir, repoRoot)
	if err == nil {
		t.Fatal("expected Assemble to fail when the recorded deployment target is newer than the declared pin, got nil error")
	}
	if !strings.Contains(err.Error(), "15.0") || !strings.Contains(err.Error(), "14.0") {
		t.Errorf("error does not name both the recorded and declared targets: %v", err)
	}
}

func TestAssembleAcceptsAppleDeploymentTargetOlderThanDeclaredPin(t *testing.T) {
	// An artifact that supports an OLDER (more permissive) minimum than
	// currently declared is still a valid, portable release candidate --
	// only "newer than declared" is a rejection.
	bundleDir, repoRoot := releasebundletest.NewBundle(t, releasebundletest.Opts{
		AppleMACOSDeploymentTargetOverride: "12.0",
	})

	if _, err := releasebundle.Assemble(bundleDir, repoRoot); err != nil {
		t.Fatalf("Assemble rejected an older-than-declared (more permissive) deployment target: %v", err)
	}
}

func TestAssembleRejectsMissingAppleDeploymentTargetPinFile(t *testing.T) {
	bundleDir, repoRoot := releasebundletest.NewBundle(t, releasebundletest.Opts{})
	pinPath := filepath.Join(repoRoot, "clients", "native", "apple-deployment-target.pin.json")
	if err := os.Remove(pinPath); err != nil {
		t.Fatal(err)
	}
	// The removal itself makes the checkout dirty relative to the commit
	// staged artifacts recorded; commit the removal and re-point both
	// staged manifests at the new HEAD so this test isolates "pin file
	// absent" from the separate, already-covered "dirty checkout"/
	// "stale revision" rejections.
	commitRemoval(t, repoRoot, pinPath)
	retargetStagedRevision(t, bundleDir, repoRoot)

	_, err := releasebundle.Assemble(bundleDir, repoRoot)
	if err == nil {
		t.Fatal("expected Assemble to fail when the declared Apple deployment-target pin file is missing, got nil error")
	}
	if !strings.Contains(err.Error(), "apple-deployment-target.pin.json") {
		t.Errorf("error does not name the missing pin file: %v", err)
	}
}

func TestAssembleRejectsMalformedAppleDeploymentTargetPin(t *testing.T) {
	bundleDir, repoRoot := releasebundletest.NewBundle(t, releasebundletest.Opts{})
	pinPath := filepath.Join(repoRoot, "clients", "native", "apple-deployment-target.pin.json")
	if err := os.WriteFile(pinPath, []byte(`{"macos_minimum_deployment_target":"not-a-version"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	commitAll(t, repoRoot, "corrupt apple deployment-target pin")
	retargetStagedRevision(t, bundleDir, repoRoot)

	_, err := releasebundle.Assemble(bundleDir, repoRoot)
	if err == nil {
		t.Fatal("expected Assemble to fail on a malformed declared Apple deployment-target pin, got nil error")
	}
	if !strings.Contains(err.Error(), "apple-deployment-target.pin.json") {
		t.Errorf("error does not name the malformed pin file: %v", err)
	}
}

// retargetStagedRevision re-points bundleDir's staged Apple and Android
// manifests' ares_core_source_revision at repoRoot's current HEAD, so a
// test that commits an additional change to repoRoot (to reach a specific
// tracked-file state) does not incidentally trip the separate, unrelated
// "stale/dirty revision" rejection while isolating a different check.
func retargetStagedRevision(t *testing.T, bundleDir, repoRoot string) {
	t.Helper()
	cmd := exec.Command("git", "rev-parse", "HEAD")
	cmd.Dir = repoRoot
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	head := strings.TrimSpace(string(out))
	overwriteManifestField(t, filepath.Join(bundleDir, "AresPrivacyCore-v1.5.1-apple.staging-manifest.json"), "ares_core_source_revision", head)
	overwriteManifestField(t, filepath.Join(bundleDir, "AresPrivacyCore-v1.5.1-android.staging-manifest.json"), "ares_core_source_revision", head)
}

// TestAssembleInspectsRealMachODeploymentTargetOnDarwin builds a real,
// tiny compiled static archive whose actual LC_BUILD_VERSION minos is
// newer than the declared pin, stages it as the macos-arm64 slice of a
// fixture xcframework whose *manifest* claims the correct (older, matching)
// target, and confirms Assemble still rejects it -- proving the inspected
// check catches a real discrepancy a staging-manifest claim alone would
// miss, exactly the bug class described in this task (a build that
// records/claims one target but actually links a newer one).
func TestAssembleInspectsRealMachODeploymentTargetOnDarwin(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("real Mach-O deployment-target inspection only runs on darwin")
	}
	if _, err := exec.LookPath("otool"); err != nil {
		t.Skip("otool is unavailable")
	}
	if _, err := exec.LookPath("clang"); err != nil {
		t.Skip("clang is unavailable")
	}

	bundleDir, repoRoot := releasebundletest.NewBundle(t, releasebundletest.Opts{})
	realLib := compileRealMachOStaticLib(t, "15.0") // newer than the fixture's declared/recorded 14.0
	replaceAppleXCFrameworkMacOSSlice(t, bundleDir, realLib)

	_, err := releasebundle.Assemble(bundleDir, repoRoot)
	if err == nil {
		t.Fatal("expected Assemble to reject a real Mach-O whose inspected minos exceeds the declared pin, got nil error")
	}
	if !strings.Contains(err.Error(), "15.0") {
		t.Errorf("error does not name the inspected mismatch: %v", err)
	}
}

// TestAssembleAcceptsRealMachOMatchingDeploymentTargetOnDarwin is the
// mirror positive case: a real compiled archive whose inspected minos
// exactly matches the declared pin must not be rejected by the inspection
// step.
func TestAssembleAcceptsRealMachOMatchingDeploymentTargetOnDarwin(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("real Mach-O deployment-target inspection only runs on darwin")
	}
	if _, err := exec.LookPath("otool"); err != nil {
		t.Skip("otool is unavailable")
	}
	if _, err := exec.LookPath("clang"); err != nil {
		t.Skip("clang is unavailable")
	}

	bundleDir, repoRoot := releasebundletest.NewBundle(t, releasebundletest.Opts{})
	realLib := compileRealMachOStaticLib(t, releasebundletest.AppleMACOSDeploymentTarget)
	replaceAppleXCFrameworkMacOSSlice(t, bundleDir, realLib)

	if _, err := releasebundle.Assemble(bundleDir, repoRoot); err != nil {
		t.Fatalf("Assemble rejected a real Mach-O whose inspected minos exactly matches the declared pin: %v", err)
	}
}

// compileRealMachOStaticLib compiles a trivial C file with an explicit
// -mmacosx-version-min and archives it into a real static library,
// returning its path. This is the "bounded real metadata probe": no
// OpenFHE build, just a few-millisecond real clang invocation to ground
// the parsing logic against genuine Mach-O bytes.
func compileRealMachOStaticLib(t *testing.T, deploymentTarget string) string {
	t.Helper()
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "t.c")
	if err := os.WriteFile(srcPath, []byte("int ares_probe(void){return 0;}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	objPath := filepath.Join(dir, "t.o")
	cmd := exec.CommandContext(context.Background(), "clang", "-mmacosx-version-min="+deploymentTarget, "-c", srcPath, "-o", objPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("clang: %v\n%s", err, out)
	}
	libPath := filepath.Join(dir, "libAresPrivacyCore.a")
	cmd = exec.CommandContext(context.Background(), "ar", "rcs", libPath, objPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ar: %v\n%s", err, out)
	}
	return libPath
}

// replaceAppleXCFrameworkMacOSSlice rewrites bundleDir's staged Apple
// xcframework zip, replacing the macos-arm64 slice's libAresPrivacyCore.a
// member with the real file at realLibPath and updating the staging
// manifest's artifact_sha256 to match (mirroring what a real build would
// have recorded for its own real output).
func replaceAppleXCFrameworkMacOSSlice(t *testing.T, bundleDir, realLibPath string) {
	t.Helper()
	artifactPath := filepath.Join(bundleDir, "AresPrivacyCore-v1.5.1-apple.xcframework.zip")
	r, err := zip.OpenReader(artifactPath)
	if err != nil {
		t.Fatal(err)
	}
	realLibBytes, err := os.ReadFile(realLibPath)
	if err != nil {
		t.Fatal(err)
	}

	rewritten := artifactPath + ".rewritten"
	out, err := os.Create(rewritten)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(out)
	for _, f := range r.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		var content []byte
		if strings.Contains("/"+f.Name, "/macos-arm64/") && strings.HasSuffix(f.Name, "libAresPrivacyCore.a") {
			content = realLibBytes
		} else {
			content, err = io.ReadAll(rc)
			if err != nil {
				t.Fatal(err)
			}
		}
		rc.Close()
		w, err := zw.Create(f.Name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(rewritten, artifactPath); err != nil {
		t.Fatal(err)
	}

	sum := sha256.Sum256(mustReadFile(t, artifactPath))
	overwriteAppleManifestField(t, bundleDir, "artifact_sha256", hex.EncodeToString(sum[:]))
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// overwriteAppleManifestField loads the staged Apple staging-manifest JSON,
// sets one top-level field to value, and writes it back -- used by
// mutation tests to construct a manifest shape NewBundle's Opts can't
// express directly (a missing field, an out-of-band field edit after
// artifact bytes were changed).
func overwriteAppleManifestField(t *testing.T, bundleDir, field, value string) {
	t.Helper()
	overwriteManifestField(t, filepath.Join(bundleDir, "AresPrivacyCore-v1.5.1-apple.staging-manifest.json"), field, value)
}

// overwriteManifestField loads the staging-manifest JSON at path, sets one
// top-level field to value (or deletes it, if value is empty), and writes
// it back.
func overwriteManifestField(t *testing.T, path, field, value string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if value == "" {
		delete(m, field)
	} else {
		m[field] = value
	}
	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatal(err)
	}
}

func commitAll(t *testing.T, repoRoot, message string) {
	t.Helper()
	cmd := exec.Command("git", "add", "-A")
	cmd.Dir = repoRoot
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git add: %v\n%s", err, out)
	}
	cmd = exec.Command("git", "commit", "-q", "-m", message)
	cmd.Dir = repoRoot
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git commit: %v\n%s", err, out)
	}
}

func commitRemoval(t *testing.T, repoRoot, path string) {
	t.Helper()
	rel, err := filepath.Rel(repoRoot, path)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("git", "rm", "-q", rel)
	cmd.Dir = repoRoot
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git rm: %v\n%s", err, out)
	}
	cmd = exec.Command("git", "commit", "-q", "-m", "remove apple deployment-target pin")
	cmd.Dir = repoRoot
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git commit: %v\n%s", err, out)
	}
}

