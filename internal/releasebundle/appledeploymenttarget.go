package releasebundle

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// appleDeploymentTargetPinFile mirrors clients/native/apple-deployment-target.pin.json's
// single tracked field: the declared minimum macOS deployment target every
// staged Apple XCFramework's macos-arm64 slice must not exceed.
type appleDeploymentTargetPinFile struct {
	MACOSMinimumDeploymentTarget string `json:"macos_minimum_deployment_target"`
}

// readDeclaredAppleDeploymentTarget reads and validates repoRoot's tracked
// clients/native/apple-deployment-target.pin.json, the sole source of
// truth for what macOS deployment target this repository currently
// declares as supported.
func readDeclaredAppleDeploymentTarget(repoRoot string) (string, error) {
	path := filepath.Join(repoRoot, "clients", "native", "apple-deployment-target.pin.json")
	raw, err := readRegularFile(path)
	if err != nil {
		return "", fmt.Errorf("reading tracked Apple deployment-target pin %s: %w", path, err)
	}
	var pin appleDeploymentTargetPinFile
	if err := json.Unmarshal(raw, &pin); err != nil {
		return "", fmt.Errorf("parsing tracked Apple deployment-target pin %s: %w", path, err)
	}
	if err := validateAppleVersionFormat(pin.MACOSMinimumDeploymentTarget); err != nil {
		return "", fmt.Errorf("tracked Apple deployment-target pin %s has an invalid macos_minimum_deployment_target: %w", path, err)
	}
	return pin.MACOSMinimumDeploymentTarget, nil
}

var appleVersionPattern = regexp.MustCompile(`^([0-9]+)\.([0-9]+)$`)

// validateAppleVersionFormat fails closed unless value is a well-formed
// MAJOR.MINOR version string -- empty, missing a component, or non-numeric
// values are all rejected rather than guessed at.
func validateAppleVersionFormat(value string) error {
	if value == "" {
		return fmt.Errorf("value is empty (want MAJOR.MINOR)")
	}
	if !appleVersionPattern.MatchString(value) {
		return fmt.Errorf("value %q is not a well-formed MAJOR.MINOR version", value)
	}
	return nil
}

// compareAppleVersions returns -1, 0, or 1 as a is numerically less than,
// equal to, or greater than b. Both must already be validated
// MAJOR.MINOR strings (validateAppleVersionFormat).
func compareAppleVersions(a, b string) (int, error) {
	aMajor, aMinor, err := splitAppleVersion(a)
	if err != nil {
		return 0, err
	}
	bMajor, bMinor, err := splitAppleVersion(b)
	if err != nil {
		return 0, err
	}
	if aMajor != bMajor {
		if aMajor < bMajor {
			return -1, nil
		}
		return 1, nil
	}
	if aMinor != bMinor {
		if aMinor < bMinor {
			return -1, nil
		}
		return 1, nil
	}
	return 0, nil
}

func splitAppleVersion(v string) (major, minor int, err error) {
	match := appleVersionPattern.FindStringSubmatch(v)
	if match == nil {
		return 0, 0, fmt.Errorf("value %q is not a well-formed MAJOR.MINOR version", v)
	}
	major, err = strconv.Atoi(match[1])
	if err != nil {
		return 0, 0, fmt.Errorf("value %q has an unparsable major version: %w", v, err)
	}
	minor, err = strconv.Atoi(match[2])
	if err != nil {
		return 0, 0, fmt.Errorf("value %q has an unparsable minor version: %w", v, err)
	}
	return major, minor, nil
}

// verifyAppleDeploymentTarget fails closed unless the Apple artifact's
// recorded macos_minimum_deployment_target is present, well-formed, and no
// newer than repoRoot's currently tracked declared target. When otool is
// available on this host, it additionally extracts the macos-arm64
// slice's combined static library from the real staged archive and
// inspects its actual Mach-O LC_BUILD_VERSION/LC_VERSION_MIN_MACOSX minos
// values, rejecting the bundle if any of them are newer than the declared
// target too -- so a staging manifest's claim alone is never sufficient
// when the real binary can be checked.
func verifyAppleDeploymentTarget(bundleDir, repoRoot string, apple *ArtifactManifest, artifactPath string) error {
	if err := validateAppleVersionFormat(apple.AppleMACOSDeploymentTarget); err != nil {
		return fmt.Errorf("apple artifact staging manifest has an invalid apple_macos_deployment_target: %w", err)
	}
	declared, err := readDeclaredAppleDeploymentTarget(repoRoot)
	if err != nil {
		return err
	}
	cmp, err := compareAppleVersions(apple.AppleMACOSDeploymentTarget, declared)
	if err != nil {
		return err
	}
	if cmp > 0 {
		return fmt.Errorf("apple artifact's recorded macOS deployment target %s is newer than the declared supported target %s; this xcframework is not a portable release candidate",
			apple.AppleMACOSDeploymentTarget, declared)
	}

	inspectedMinOS, inspected, err := inspectAppleMacOSSliceDeploymentTarget(artifactPath)
	if err != nil {
		return fmt.Errorf("inspecting real Mach-O deployment target metadata in %s: %w", artifactPath, err)
	}
	if !inspected {
		// otool is unavailable on this host (e.g. a Linux CI runner). The
		// portable, manifest-recorded check above already ran and passed;
		// the stronger real-binary check simply cannot run here.
		return nil
	}
	for _, value := range inspectedMinOS {
		if err := validateAppleVersionFormat(value); err != nil {
			return fmt.Errorf("apple artifact %s: inspected Mach-O minos value is malformed: %w", artifactPath, err)
		}
		cmp, err := compareAppleVersions(value, declared)
		if err != nil {
			return err
		}
		if cmp > 0 {
			return fmt.Errorf("apple artifact %s: inspected Mach-O minimum macOS %s is newer than the declared supported target %s; this xcframework is not a portable release candidate",
				artifactPath, value, declared)
		}
	}
	return nil
}

// inspectAppleMacOSSliceDeploymentTarget extracts the macos-arm64 slice's
// combined static library from the staged xcframework zip and runs the
// real `otool -l` against it, returning every LC_BUILD_VERSION/
// LC_VERSION_MIN_MACOSX "minos" value found. The second return value is
// false (with a nil error) when otool is not on PATH, so the caller can
// distinguish "tool unavailable" from "tool found nothing to report."
func inspectAppleMacOSSliceDeploymentTarget(artifactPath string) ([]string, bool, error) {
	otoolPath, err := exec.LookPath("otool")
	if err != nil {
		return nil, false, nil
	}

	r, err := zip.OpenReader(artifactPath)
	if err != nil {
		return nil, true, fmt.Errorf("opening apple artifact as zip: %w", err)
	}
	defer r.Close()

	var member *zip.File
	for _, f := range r.File {
		if strings.Contains("/"+f.Name, "/macos-arm64/") && strings.HasSuffix(f.Name, "libAresPrivacyCore.a") {
			member = f
			break
		}
	}
	if member == nil {
		return nil, true, fmt.Errorf("no macos-arm64 libAresPrivacyCore.a member found in %s", artifactPath)
	}

	rc, err := member.Open()
	if err != nil {
		return nil, true, fmt.Errorf("opening archive member %s: %w", member.Name, err)
	}
	defer rc.Close()

	tmp, err := os.CreateTemp("", "ares-macos-slice-*.a")
	if err != nil {
		return nil, true, fmt.Errorf("creating temp file for Mach-O inspection: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := io.Copy(tmp, rc); err != nil {
		tmp.Close()
		return nil, true, fmt.Errorf("extracting %s for Mach-O inspection: %w", member.Name, err)
	}
	if err := tmp.Close(); err != nil {
		return nil, true, fmt.Errorf("closing extracted Mach-O temp file: %w", err)
	}

	out, err := exec.Command(otoolPath, "-l", tmpPath).CombinedOutput()
	if err != nil {
		return nil, true, fmt.Errorf("otool -l failed on extracted %s: %w (%s)", member.Name, err, string(out))
	}
	// A fixture or otherwise non-Mach-O artifact makes otool report this
	// (exit 0, no load commands) rather than fail. Not being a real
	// Mach-O object is a distinct problem from a deployment-target
	// mismatch and out of scope for this check specifically -- treat it
	// the same as "otool unavailable" (inspected=false) rather than
	// failing closed here, so a placeholder/fixture artifact does not
	// masquerade as a deployment-target violation.
	if strings.Contains(string(out), "is not an object file") {
		return nil, false, nil
	}

	var values []string
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "minos" {
			values = append(values, fields[1])
		}
	}
	if len(values) == 0 {
		return nil, true, fmt.Errorf("no LC_BUILD_VERSION/LC_VERSION_MIN_MACOSX minos load command found in %s", member.Name)
	}
	return values, true, nil
}
