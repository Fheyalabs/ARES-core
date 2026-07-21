package releasebundle

import (
	"archive/zip"
	"fmt"
	"path"
	"strings"
	"unicode/utf8"
)

// validateZIPMemberNames rejects names whose interpretation can differ
// between ZIP readers or filesystems. It also rejects exact and
// normalization-equivalent duplicates before callers select any member.
func validateZIPMemberNames(files []*zip.File) error {
	seen := make(map[string]string, len(files))
	for _, file := range files {
		name := file.Name
		normalized := normalizedZIPMemberName(name)
		if previous, ok := seen[normalized]; ok {
			return fmt.Errorf("duplicate or normalization-equivalent ZIP member %q collides with %q", name, previous)
		}
		seen[normalized] = name
		if err := validateZIPMemberName(name); err != nil {
			return err
		}
	}
	return nil
}

func normalizedZIPMemberName(name string) string {
	normalized := strings.ReplaceAll(name, `\`, "/")
	normalized = strings.TrimLeft(normalized, "/")
	return path.Clean(strings.TrimSuffix(normalized, "/"))
}

func validateZIPMemberName(name string) error {
	if name == "" || !utf8.ValidString(name) {
		return fmt.Errorf("ZIP member name %q is empty or invalid UTF-8", name)
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("ZIP member %q contains a control character", name)
		}
	}
	if strings.Contains(name, `\`) {
		return fmt.Errorf("ZIP member %q uses a non-canonical backslash separator", name)
	}
	if strings.HasPrefix(name, "/") || hasWindowsDrivePrefix(name) {
		return fmt.Errorf("ZIP member %q uses an absolute path", name)
	}
	trimmed := strings.TrimSuffix(name, "/")
	if trimmed == "" || path.Clean(trimmed) != trimmed {
		return fmt.Errorf("ZIP member %q is not a canonical relative path", name)
	}
	for _, component := range strings.Split(trimmed, "/") {
		if component == "." || component == ".." {
			return fmt.Errorf("ZIP member %q contains an unsafe path component", name)
		}
	}
	return nil
}

func hasWindowsDrivePrefix(name string) bool {
	return len(name) >= 3 && ((name[0] >= 'A' && name[0] <= 'Z') || (name[0] >= 'a' && name[0] <= 'z')) && name[1] == ':' && name[2] == '/'
}
