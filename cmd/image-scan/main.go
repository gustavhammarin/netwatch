package main

import (
	"encoding/json"
	"fmt"
	"netwatch/internal/image-scan/image"
	"netwatch/internal/image-scan/osv"
	"netwatch/internal/image-scan/parser"
	"os"
)

func main() {
	imageName := os.Args[1]
	layers, err := image.ExtractFromDaemon(imageName)
	if err != nil {
		fmt.Print(err)
	}
	packages := collectPackages(layers)
	if err := writePackagesToJSON(packages); err != nil {
		fmt.Print(err)
	}

	var findings []osv.Finding

	for _, pkg := range packages{
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

func collectPackages(layers []image.Layer) []parser.Package {
	var packages []parser.Package

	for _, layer := range layers {
		content, ok := layer.Files["lib/apk/db/installed"]
		if !ok {
			continue
		}
		pkgs := parser.ParseAlpine(content)
		packages = append(packages, pkgs...)
	}

	return packages
}
