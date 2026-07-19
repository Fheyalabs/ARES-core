package releasebundle

import (
	"fmt"
	"regexp"
	"strings"
)

// forbiddenSwiftManifestSubstrings must never appear anywhere in
// clients/swift/Package.release.swift. Each represents a way
// development-only dependency resolution (a workstation toolchain path or
// an environment-variable override) could substitute for the staged,
// hash-verified binary target this manifest is supposed to consume
// unconditionally.
var forbiddenSwiftManifestSubstrings = []string{
	"ProcessInfo.processInfo.environment",
	"file://",
	"/usr/local",
	"/opt/homebrew",
	"ARES_OPENFHE",
	"ARES_CORE_SWIFT_PATH",
}

// requiredSwiftManifestEvidence are substrings that must be present:
// positive proof the manifest actually wires the staged bridge binary
// target, not merely proof it lacks forbidden patterns.
var requiredSwiftManifestEvidence = []string{
	`.binaryTarget(name: "COpenFHEBridge"`,
}

var packageCallStart = regexp.MustCompile(`\.package\s*\(`)

// checkSwiftReleaseManifest fails closed if raw contains any forbidden
// local-path/environment-substitution pattern, declares a local
// (filesystem-path) package dependency, or is missing positive evidence
// that it binds the staged COpenFHEBridge binary target.
func checkSwiftReleaseManifest(raw string) error {
	for _, forbidden := range forbiddenSwiftManifestSubstrings {
		if strings.Contains(raw, forbidden) {
			return fmt.Errorf("clients/swift/Package.release.swift contains a forbidden local-path/environment dependency substitution pattern: %q", forbidden)
		}
	}
	if err := rejectLocalPackagePathDependencies(raw); err != nil {
		return err
	}
	for _, want := range requiredSwiftManifestEvidence {
		if !strings.Contains(raw, want) {
			return fmt.Errorf("clients/swift/Package.release.swift is missing required evidence of the staged bridge binary target: %q", want)
		}
	}
	return nil
}

// rejectLocalPackagePathDependencies finds every `.package(` (whitespace
// before `(` tolerated) call, walks its argument list by paren-balanced
// depth (so a nested call like URL(string:) inside the argument list does
// not confuse where the .package(...) call actually ends), and fails
// closed if that call's argument list contains a path: argument -- a local
// filesystem dependency -- or if the call is never terminated.
func rejectLocalPackagePathDependencies(raw string) error {
	searchFrom := 0
	for {
		loc := packageCallStart.FindStringIndex(raw[searchFrom:])
		if loc == nil {
			return nil
		}
		start := searchFrom + loc[1] // just past the opening '('
		depth := 1
		i := start
		for i < len(raw) && depth > 0 {
			switch raw[i] {
			case '(':
				depth++
			case ')':
				depth--
			}
			i++
		}
		if depth != 0 {
			return fmt.Errorf("clients/swift/Package.release.swift has an unterminated .package( call")
		}
		call := raw[start : i-1]
		if strings.Contains(call, "path:") {
			return fmt.Errorf("clients/swift/Package.release.swift declares a local path package dependency: .package(%s)", call)
		}
		searchFrom = i
	}
}
