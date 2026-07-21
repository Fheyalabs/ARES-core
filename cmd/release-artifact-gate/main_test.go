package main_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Fheyalabs/ares-core/internal/releasebundle/releasebundletest"
)

// buildGateBinary builds the release-artifact-gate CLI once per test
// process into a temp directory and returns its path, so the end-to-end
// test below drives it as a real subprocess (argument parsing, exit codes,
// and stdout/stderr as an actual CLI user would experience), not just as
// internal function calls.
func buildGateBinary(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "release-artifact-gate")
	pkgDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Dir = pkgDir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("building release-artifact-gate: %v\n%s", err, out)
	}
	return bin
}

func TestEndToEndAssembleThenVerifyAcceptsAValidBundle(t *testing.T) {
	bin := buildGateBinary(t)
	bundleDir, repoRoot := releasebundletest.NewBundle(t, releasebundletest.Opts{})
	releasebundletest.RequireHermeticOtool(t)
	manifestPath := filepath.Join(t.TempDir(), "release-cache-manifest.json")

	assembleOut, err := exec.Command(bin, "assemble",
		"-bundle-dir="+bundleDir,
		"-repo-root="+repoRoot,
		"-out="+manifestPath,
	).CombinedOutput()
	if err != nil {
		t.Fatalf("assemble subcommand failed: %v\n%s", err, assembleOut)
	}
	if !strings.Contains(string(assembleOut), manifestPath) {
		t.Errorf("assemble output does not mention the manifest path: %s", assembleOut)
	}
	if _, err := os.Stat(manifestPath); err != nil {
		t.Fatalf("assemble did not write a manifest: %v", err)
	}

	verifyOut, err := exec.Command(bin, "verify",
		"-manifest="+manifestPath,
		"-bundle-dir="+bundleDir,
		"-repo-root="+repoRoot,
	).CombinedOutput()
	if err != nil {
		t.Fatalf("verify subcommand failed on a valid bundle: %v\n%s", err, verifyOut)
	}
	if !strings.Contains(string(verifyOut), "verified OK") {
		t.Errorf("verify output does not confirm success: %s", verifyOut)
	}
}

func TestEndToEndAssembleFailsClosedWithoutOtool(t *testing.T) {
	bin := buildGateBinary(t)
	bundleDir, repoRoot := releasebundletest.NewBundle(t, releasebundletest.Opts{})
	manifestPath := filepath.Join(t.TempDir(), "release-cache-manifest.json")
	toolDir := t.TempDir()
	gitPath, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(gitPath, filepath.Join(toolDir, "git")); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(bin, "assemble",
		"-bundle-dir="+bundleDir,
		"-repo-root="+repoRoot,
		"-out="+manifestPath,
	)
	cmd.Env = environmentWithPath(toolDir)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected assemble to fail without otool, got success:\n%s", out)
	}
	if !strings.Contains(string(out), "otool") {
		t.Errorf("failure does not identify unavailable otool: %s", out)
	}
	if _, statErr := os.Stat(manifestPath); statErr == nil {
		t.Fatal("assemble must not write a manifest when otool is unavailable")
	}
}

func environmentWithPath(path string) []string {
	env := make([]string, 0, len(os.Environ()))
	for _, item := range os.Environ() {
		if strings.HasPrefix(item, "PATH=") {
			continue
		}
		env = append(env, item)
	}
	return append(env, "PATH="+path)
}

func TestEndToEndVerifyRejectsATamperedArtifact(t *testing.T) {
	bin := buildGateBinary(t)
	bundleDir, repoRoot := releasebundletest.NewBundle(t, releasebundletest.Opts{})
	manifestPath := filepath.Join(t.TempDir(), "release-cache-manifest.json")

	if out, err := exec.Command(bin, "assemble",
		"-bundle-dir="+bundleDir,
		"-repo-root="+repoRoot,
		"-out="+manifestPath,
	).CombinedOutput(); err != nil {
		t.Fatalf("assemble subcommand failed: %v\n%s", err, out)
	}

	// Corrupt the staged artifact after a valid manifest was assembled from
	// it, simulating a substituted/corrupted bundle reaching the gate.
	releasebundletest.TamperFile(t, filepath.Join(bundleDir, "AresPrivacyCore-v1.5.1-android.aar"))

	cmd := exec.Command(bin, "verify",
		"-manifest="+manifestPath,
		"-bundle-dir="+bundleDir,
		"-repo-root="+repoRoot,
	)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected verify to exit nonzero against a tampered bundle, got success:\n%s", out)
	}
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("expected an *exec.ExitError, got %T: %v", err, err)
	}
	if exitErr.ExitCode() == 0 {
		t.Fatalf("expected a nonzero exit code, got 0")
	}
	if !strings.Contains(string(out), "release-artifact-gate:") {
		t.Errorf("verify stderr does not look like our fail() output: %s", out)
	}
}

func TestEndToEndAssembleRejectsMismatchedSourceRevision(t *testing.T) {
	bin := buildGateBinary(t)
	bundleDir, repoRoot := releasebundletest.NewBundle(t, releasebundletest.Opts{
		AndroidAresRevOverride: "0000000000000000000000000000000000dead",
	})
	manifestPath := filepath.Join(t.TempDir(), "release-cache-manifest.json")

	cmd := exec.Command(bin, "assemble",
		"-bundle-dir="+bundleDir,
		"-repo-root="+repoRoot,
		"-out="+manifestPath,
	)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected assemble to exit nonzero on mismatched source revision, got success:\n%s", out)
	}
	if _, statErr := os.Stat(manifestPath); statErr == nil {
		t.Fatal("assemble must not write a manifest when it fails closed")
	}
}
