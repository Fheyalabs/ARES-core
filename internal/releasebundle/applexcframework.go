package releasebundle

import (
	"archive/zip"
	"fmt"
	"strings"
)

// checkAppleXCFrameworkContents fails closed unless every platform slice in
// requiredPlatforms has its own directory entry (a path segment matching
// the slice name exactly) containing libAresPrivacyCore.a and the
// COpenFHEBridge module headers. It never trusts the staging manifest's own
// target_architectures claim: it opens the actual archive and looks.
func checkAppleXCFrameworkContents(path string, requiredPlatforms []string) error {
	r, err := zip.OpenReader(path)
	if err != nil {
		return fmt.Errorf("opening apple artifact %s as zip: %w", path, err)
	}
	defer r.Close()

	names := make([]string, 0, len(r.File))
	for _, f := range r.File {
		names = append(names, f.Name)
	}

	for _, slice := range requiredPlatforms {
		prefix := "/" + slice + "/"
		var hasLib, hasHeader, hasModulemap bool
		for _, name := range names {
			if !strings.Contains("/"+name, prefix) {
				continue
			}
			switch {
			case strings.HasSuffix(name, "libAresPrivacyCore.a"):
				hasLib = true
			case strings.HasSuffix(name, "openfhe_wrapper.h"):
				hasHeader = true
			case strings.HasSuffix(name, "module.modulemap"):
				hasModulemap = true
			}
		}
		if !hasLib || !hasHeader || !hasModulemap {
			return fmt.Errorf("apple artifact %s is missing required bridge module contents for slice %s (lib=%v header=%v modulemap=%v)", path, slice, hasLib, hasHeader, hasModulemap)
		}
	}
	return nil
}
