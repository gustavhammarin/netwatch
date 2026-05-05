package image

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type Manifest struct {
	Config   string   `json:"Config"`
	RepoTags []string `json:"RepoTags"`
	Layers   []string `json:"Layers"`
}

type Layer struct {
	Files  map[string][]byte `json:"files"`
	WithOuts []string `json:"withouts"`
}

func ExtractFromDaemon(imageName string) ([]Layer, error) {
	tmpFile, err := os.CreateTemp("", "docker-image-*.tar")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}

	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	fmt.Printf("[*] Saving image %s from Docker daemon...\n", imageName)

	cmd := exec.Command("docker", "save", imageName, "-o", tmpFile.Name())

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("docker save failed: %w", err)
	}

	return extractFromTar(tmpFile.Name())

}

func extractFromTar(tarPath string) ([]Layer, error) {
	f, err := os.Open(tarPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open tar: %w", err)
	}
	defer f.Close()

	files := map[string][]byte{}

	tr := tar.NewReader(f)

	for {
		hdr, err := tr.Next()
		if err == io.EOF{
			break
		}
		if err != nil {
			return nil, fmt.Errorf("error reading tar: %w", err)
		}
		content, err := io.ReadAll(tr)
		if err != nil {
			return nil, fmt.Errorf("error reading file %s: %w",hdr.Name, err )
		}
		files[hdr.Name] = content
	}

	var manifests []Manifest
	if err := json.Unmarshal(files["manifest.json"], &manifests); err != nil {
		return nil, fmt.Errorf("failed to parse manifest.json: %w", err)
	}

	var layers []Layer
	for _, layerPath := range manifests[0].Layers{
		layer, err := extractFromLayer(files[layerPath])
		if err != nil {
			return nil, fmt.Errorf("failed to extract layer %s: %w", layerPath, err)
		}
		layers = append(layers, layer)
	}

	return layers, nil
}

func extractFromLayer(data []byte) (Layer, error) {
	layer := Layer{
		Files: make(map[string][]byte),
	}

	var tr *tar.Reader
	gzReader, err := gzip.NewReader(bytes.NewReader(data))
	if err == nil {
		tr = tar.NewReader(gzReader)
	}else{
		tr = tar.NewReader(bytes.NewReader(data))
	}

	for {
		hdr, err := tr.Next()
		if err == io.EOF{
			break
		}
		if err != nil {
			break
		}

		name := filepath.Clean(hdr.Name)
		base := filepath.Base(name)

		if strings.HasPrefix(base, ".wh"){
			if base == ".wh..wh..opq" {
				layer.WithOuts = append(layer.WithOuts, filepath.Dir(name)+"/")
			}else {
				deleted := filepath.Join(filepath.Dir(name), strings.TrimPrefix(base, ".wh."))
				layer.WithOuts = append(layer.WithOuts, deleted)
			}
			continue
		}

		if hdr.Typeflag == tar.TypeReg{
			if isInterestingFile(name){
				content, err := io.ReadAll(tr)
				if err != nil {
					continue
				}
				layer.Files[name] = content
			}
		}
	}
	return layer, nil
}

func isInterestingFile(path string) bool {
	interesting := []string{
		"lib/apk/db/installed",
		"var/lib/dpkg/status",
		"var/lib/rpm/Packages",
		"usr/lib/sysimage/rpm/Packages",
		"etc/os-release",
	}
	for _, suffix := range interesting {
		if strings.HasSuffix(path, suffix) || path == suffix {
			return true
		}
	}
	return false
}