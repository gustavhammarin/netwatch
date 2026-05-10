package scan

import (
	"context"
	"fmt"
	"net/http"
	"netwatch/internal/image-scan/image"
	"netwatch/internal/image-scan/osv"
	"netwatch/internal/image-scan/parser"
	"strings"
	"sync"
	"time"
)

// Result contains the static filesystem analysis for a container image.
type Result struct {
	Image    string           `json:"image"`
	Packages []parser.Package `json:"packages"`
	Findings []osv.Finding    `json:"findings"`
}

// EventFunc receives progress updates during image scanning.
type EventFunc func(message string)

// Image scans an image from the local Docker daemon and queries OSV for package findings.
func Image(ctx context.Context, imageName string, progress EventFunc) (Result, error) {
	if progress != nil {
		progress("saving image from Docker daemon")
	}
	img, err := image.ExtractImageFromDaemon(imageName)
	if err != nil {
		return Result{}, err
	}

	if err := ctx.Err(); err != nil {
		return Result{}, fmt.Errorf("scan cancelled: %w", err)
	}

	if progress != nil {
		progress("extracting packages from image filesystem")
	}
	packages := CollectPackages(img)

	if progress != nil {
		progress("querying OSV vulnerability database")
	}
	findings := queryFindings(ctx, packages)

	return Result{
		Image:    imageName,
		Packages: packages,
		Findings: findings,
	}, nil
}

func queryFindings(ctx context.Context, packages []parser.Package) []osv.Finding {
	type osvResult struct {
		findings []osv.Finding
	}

	results := make(chan osvResult, len(packages))
	limit := make(chan struct{}, 20)
	client := &http.Client{Timeout: 15 * time.Second}

	var wg sync.WaitGroup
	for _, pkg := range packages {
		pkg := pkg
		wg.Add(1)
		go func() {
			defer wg.Done()

			select {
			case limit <- struct{}{}:
				defer func() { <-limit }()
			case <-ctx.Done():
				return
			}

			res, err := osv.QueryOSVContext(ctx, client, pkg)
			if err != nil {
				return
			}
			results <- osvResult{findings: res}
		}()
	}
	wg.Wait()
	close(results)

	var findings []osv.Finding
	for result := range results {
		findings = append(findings, result.findings...)
	}
	return findings
}

// CollectPackages returns unique packages discovered in the image rootfs and layers.
func CollectPackages(img image.Image) []parser.Package {
	var packages []parser.Package
	seen := make(map[string]struct{})

	variants := img.Variants
	if len(variants) == 0 {
		variants = []image.Variant{{
			Config:   img.Config,
			RepoTags: img.RepoTags,
			Layers:   img.Layers,
			RootFS:   img.RootFS,
		}}
	}

	for _, variant := range variants {
		addPackages(&packages, seen, collectPackagesFromFiles(variant.RootFS, variant.RootFS, variant.Config)...)
		for _, layer := range variant.Layers {
			addPackages(&packages, seen, collectPackagesFromFiles(layer.Files, variant.RootFS, variant.Config)...)
		}
	}

	return packages
}

func collectPackagesFromFiles(files map[string][]byte, ecosystemRootFS map[string][]byte, config image.Config) []parser.Package {
	var packages []parser.Package

	if content, ok := files["lib/apk/db/installed"]; ok {
		packages = append(packages, parser.ParseAlpine(content)...)
	}
	if content, ok := files["var/lib/dpkg/status"]; ok {
		packages = append(packages, parser.ParseDebian(content, dpkgEcosystem(ecosystemRootFS))...)
	}
	for path, content := range files {
		if strings.HasPrefix(path, "var/lib/dpkg/status.d/") &&
			!strings.HasSuffix(path, ".md5sums") {
			packages = append(packages, parser.ParseDebian(content, dpkgEcosystem(ecosystemRootFS))...)
		}
		if isNPMLockfile(path) {
			packages = append(packages, parser.ParseNPMPackageLock(content)...)
		}
		if isNodeModulePackageJSON(path) {
			packages = append(packages, parser.ParseNPMPackageJSON(content)...)
		}
	}

	applyImagePlatform(packages, config.OS, config.Architecture, config.Variant)
	return packages
}

func isNPMLockfile(path string) bool {
	return strings.HasSuffix(path, "/package-lock.json") ||
		path == "package-lock.json" ||
		strings.HasSuffix(path, "/npm-shrinkwrap.json") ||
		path == "npm-shrinkwrap.json"
}

func isNodeModulePackageJSON(path string) bool {
	return strings.HasSuffix(path, "/package.json") &&
		strings.Contains(path, "node_modules/")
}

func addPackages(packages *[]parser.Package, seen map[string]struct{}, candidates ...parser.Package) {
	for _, pkg := range candidates {
		key := packageKey(pkg)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		*packages = append(*packages, pkg)
	}
}

func packageKey(pkg parser.Package) string {
	return strings.Join([]string{
		pkg.Ecosystem,
		pkg.Name,
		pkg.Version,
		pkg.Architecture,
		pkg.ImageOS,
		pkg.ImageArchitecture,
	}, "\x00")
}

func applyImagePlatform(packages []parser.Package, osName string, architecture string, variant string) {
	if architecture != "" && variant != "" {
		architecture += "/" + variant
	}
	for i := range packages {
		packages[i].ImageOS = osName
		packages[i].ImageArchitecture = architecture
		if packages[i].Architecture == "" {
			packages[i].Architecture = architecture
		}
	}
}

func dpkgEcosystem(rootfs map[string][]byte) string {
	content, ok := rootfs["etc/os-release"]
	if !ok {
		return "Debian"
	}

	values := parser.ParseOSRelease(content)
	switch values["ID"] {
	case "ubuntu":
		return "Ubuntu"
	case "debian":
		return "Debian"
	default:
		if idLike, ok := values["ID_LIKE"]; ok && containsWord(idLike, "debian") {
			return "Debian"
		}
		return "Debian"
	}
}

func containsWord(value string, word string) bool {
	for _, field := range strings.Fields(value) {
		if field == word {
			return true
		}
	}
	return false
}
