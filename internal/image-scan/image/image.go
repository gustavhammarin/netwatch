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

type Config struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
	Variant      string `json:"variant"`
}

type Image struct {
	Config   Config            `json:"config"`
	RepoTags []string          `json:"repoTags"`
	Layers   []Layer           `json:"layers"`
	RootFS   map[string][]byte `json:"rootfs"`
	Variants []Variant         `json:"variants"`
}

type Variant struct {
	Config   Config            `json:"config"`
	RepoTags []string          `json:"repoTags"`
	Layers   []Layer           `json:"layers"`
	RootFS   map[string][]byte `json:"rootfs"`
}

type Layer struct {
	Files         map[string][]byte `json:"files"`
	Whiteouts     []string          `json:"whiteouts"`
	Path          string            `json:"path,omitempty"`
	ManifestIndex int               `json:"manifestIndex,omitempty"`
	LayerIndex    int               `json:"layerIndex,omitempty"`
}

func ExtractFromDaemon(imageName string) ([]Layer, error) {
	img, err := ExtractImageFromDaemon(imageName)
	if err != nil {
		return nil, err
	}
	return img.Layers, nil
}

func ExtractImageFromDaemon(imageName string) (Image, error) {
	tmpFile, err := os.CreateTemp("", "docker-image-*.tar")
	if err != nil {
		return Image{}, fmt.Errorf("failed to create temp file: %w", err)
	}

	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	fmt.Printf("[*] Saving image %s from Docker daemon...\n", imageName)

	cmd := exec.Command("docker", "save", imageName, "-o", tmpFile.Name())

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return Image{}, fmt.Errorf("docker save failed: %w", err)
	}

	return extractFromTar(tmpFile.Name())

}

func extractFromTar(tarPath string) (Image, error) {
	f, err := os.Open(tarPath)
	if err != nil {
		return Image{}, fmt.Errorf("failed to open tar: %w", err)
	}
	defer f.Close()

	files := map[string][]byte{}

	tr := tar.NewReader(f)

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return Image{}, fmt.Errorf("error reading tar: %w", err)
		}
		content, err := io.ReadAll(tr)
		if err != nil {
			return Image{}, fmt.Errorf("error reading file %s: %w", hdr.Name, err)
		}
		files[hdr.Name] = content
	}

	var manifests []Manifest
	if err := json.Unmarshal(files["manifest.json"], &manifests); err != nil {
		return Image{}, fmt.Errorf("failed to parse manifest.json: %w", err)
	}
	if len(manifests) == 0 {
		return Image{}, fmt.Errorf("image archive has no manifests")
	}

	var variants []Variant
	var allLayers []Layer
	for manifestIndex, manifest := range manifests {
		var config Config
		if configData, ok := files[manifest.Config]; ok {
			if err := json.Unmarshal(configData, &config); err != nil {
				return Image{}, fmt.Errorf("failed to parse image config %s: %w", manifest.Config, err)
			}
		}

		var layers []Layer
		for layerIndex, layerPath := range manifest.Layers {
			layerData, ok := files[layerPath]
			if !ok {
				return Image{}, fmt.Errorf("image archive is missing layer %s", layerPath)
			}
			layer, err := extractFromLayer(layerData)
			if err != nil {
				return Image{}, fmt.Errorf("failed to extract layer %s: %w", layerPath, err)
			}
			layer.Path = layerPath
			layer.ManifestIndex = manifestIndex
			layer.LayerIndex = layerIndex
			layers = append(layers, layer)
		}

		rootfs := MergeLayers(layers)
		variants = append(variants, Variant{
			Config:   config,
			RepoTags: manifest.RepoTags,
			Layers:   layers,
			RootFS:   rootfs,
		})
		allLayers = append(allLayers, layers...)
	}

	return Image{
		Config:   variants[0].Config,
		RepoTags: variants[0].RepoTags,
		Layers:   allLayers,
		RootFS:   variants[0].RootFS,
		Variants: variants,
	}, nil
}

func extractFromLayer(data []byte) (Layer, error) {
	layer := Layer{
		Files: make(map[string][]byte),
	}

	var tr *tar.Reader
	gzReader, err := gzip.NewReader(bytes.NewReader(data))
	if err == nil {
		defer gzReader.Close()
		tr = tar.NewReader(gzReader)
	} else {
		tr = tar.NewReader(bytes.NewReader(data))
	}

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}

		name := cleanArchivePath(hdr.Name)
		if name == "" {
			continue
		}
		base := filepath.Base(name)

		if strings.HasPrefix(base, ".wh") {
			if base == ".wh..wh..opq" {
				layer.Whiteouts = append(layer.Whiteouts, cleanArchivePath(filepath.Dir(name))+"/")
			} else {
				deleted := filepath.Join(filepath.Dir(name), strings.TrimPrefix(base, ".wh."))
				layer.Whiteouts = append(layer.Whiteouts, cleanArchivePath(deleted))
			}
			continue
		}

		if hdr.Typeflag == tar.TypeReg {
			if isInterestingFile(name) {
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

func MergeLayers(layers []Layer) map[string][]byte {
	rootfs := make(map[string][]byte)
	for _, layer := range layers {
		for _, whiteout := range layer.Whiteouts {
			if whiteout == "/" {
				for path := range rootfs {
					delete(rootfs, path)
				}
				continue
			}
			if strings.HasSuffix(whiteout, "/") {
				dir := strings.TrimSuffix(whiteout, "/")
				for path := range rootfs {
					if path == dir || strings.HasPrefix(path, dir+"/") {
						delete(rootfs, path)
					}
				}
				continue
			}
			delete(rootfs, whiteout)
		}
		for path, content := range layer.Files {
			rootfs[path] = content
		}
	}
	return rootfs
}

func isInterestingFile(path string) bool {
	interesting := []string{
		"lib/apk/db/installed",
		"var/lib/dpkg/status",
		"var/lib/rpm/Packages",
		"usr/lib/sysimage/rpm/Packages",
		"var/lib/rpm/rpmdb.sqlite",
		"usr/lib/sysimage/rpm/rpmdb.sqlite",
		"etc/os-release",
	}
	base := filepath.Base(path)
	if base == "package-lock.json" || base == "npm-shrinkwrap.json" {
		return true
	}
	if base == "package.json" && strings.Contains(path, "node_modules/") {
		return true
	}
	if strings.HasPrefix(path, "var/lib/dpkg/status.d/") &&
		!strings.HasSuffix(path, ".md5sums") {
		return true
	}
	for _, suffix := range interesting {
		if strings.HasSuffix(path, suffix) || path == suffix {
			return true
		}
	}
	return false
}

func cleanArchivePath(path string) string {
	cleaned := strings.TrimPrefix(filepath.Clean(path), "/")
	if cleaned == "." {
		return ""
	}
	return cleaned
}
