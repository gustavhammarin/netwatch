package main

import (
	"encoding/json"
	"fmt"
	"netwatch/internal/image-scan/image"
	"netwatch/internal/image-scan/osv"
	"netwatch/internal/image-scan/parser"
	"os"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: image-scan <image>")
		os.Exit(2)
	}

	imageName := os.Args[1]
	img, err := image.ExtractImageFromDaemon(imageName)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	packages := collectPackages(img)
	if err := writePackagesToJSON(packages); err != nil {
		fmt.Print(err)
	}

	var findings []osv.Finding

	for _, pkg := range packages {
		res, err := osv.QueryOSV(pkg)
		if err != nil {
			fmt.Print(err)
		}
		if res == nil {
			continue
		}
		findings = append(findings, res...)
	}

	if err := writeFindingsToJSON(findings); err != nil {
		fmt.Print(err)
	}

}

func writePackagesToJSON(pkgs []parser.Package) error {
	f, err := os.Create("packages.json")
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(pkgs); err != nil {
		return fmt.Errorf("failed to write json: %w", err)
	}
	return nil
}
func writeFindingsToJSON(findings []osv.Finding) error {
	f, err := os.Create("findings.json")
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(findings); err != nil {
		return fmt.Errorf("failed to write json: %w", err)
	}
	return nil
}

func collectPackages(img image.Image) []parser.Package {
	var packages []parser.Package

	if content, ok := img.RootFS["lib/apk/db/installed"]; ok {
		packages = append(packages, parser.ParseAlpine(content)...)
	}
	if content, ok := img.RootFS["var/lib/dpkg/status"]; ok {
		packages = append(packages, parser.ParseDebian(content, dpkgEcosystem(img.RootFS))...)
	}

	applyImagePlatform(packages, img.Config.OS, img.Config.Architecture, img.Config.Variant)
	return packages
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
