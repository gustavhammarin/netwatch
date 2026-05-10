package parser

import (
	"encoding/json"
	"strings"
)

type Package struct {
	Name              string `json:"name"`
	Version           string `json:"version"`
	Architecture      string `json:"architecture"`
	Ecosystem         string `json:"ecosystem"`
	ImageOS           string `json:"imageOs,omitempty"`
	ImageArchitecture string `json:"imageArchitecture,omitempty"`
}

func ParseAlpine(content []byte) []Package {
	var packages []Package
	var current Package
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		if line == "" {
			packages, current = appendPackage(packages, current, "Alpine")
			continue
		}
		if len(line) < 3 || line[1] != ':' {
			continue
		}
		key := string(line[0])
		value := strings.TrimSpace(line[2:])

		switch key {
		case "P":
			current.Name = value
		case "V":
			current.Version = value
		case "A":
			current.Architecture = value
		}
	}
	packages, _ = appendPackage(packages, current, "Alpine")
	return packages
}

func ParseDebian(content []byte, ecosystem ...string) []Package {
	var packages []Package
	var current Package
	name := "Debian"
	if len(ecosystem) > 0 && ecosystem[0] != "" {
		name = ecosystem[0]
	}

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			packages, current = appendPackage(packages, current, name)
			continue
		}

		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			continue
		}

		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}

		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)

		switch key {
		case "Package":
			current.Name = value
		case "Version":
			current.Version = value
		case "Architecture":
			current.Architecture = value
		}
	}

	packages, _ = appendPackage(packages, current, name)
	return packages
}

func ParseOSRelease(content []byte) map[string]string {
	values := make(map[string]string)
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		values[key] = strings.Trim(strings.TrimSpace(value), `"`)
	}
	return values
}

type npmPackageLock struct {
	Packages     map[string]npmPackage    `json:"packages"`
	Dependencies map[string]npmDependency `json:"dependencies"`
}

type npmPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type npmDependency struct {
	Version      string                   `json:"version"`
	Dependencies map[string]npmDependency `json:"dependencies"`
}

func ParseNPMPackageLock(content []byte) []Package {
	var lock npmPackageLock
	if err := json.Unmarshal(content, &lock); err != nil {
		return nil
	}

	var packages []Package
	seen := make(map[string]struct{})
	for path, pkg := range lock.Packages {
		if path == "" {
			continue
		}
		name := npmPackageNameFromPath(path)
		if pkg.Name != "" {
			name = pkg.Name
		}
		addNPMPackage(&packages, seen, name, pkg.Version)
	}
	for name, dep := range lock.Dependencies {
		collectNPMDependency(&packages, seen, name, dep)
	}
	return packages
}

func ParseNPMPackageJSON(content []byte) []Package {
	var pkg npmPackage
	if err := json.Unmarshal(content, &pkg); err != nil {
		return nil
	}
	if pkg.Name == "" || pkg.Version == "" {
		return nil
	}
	return []Package{{
		Name:      pkg.Name,
		Version:   pkg.Version,
		Ecosystem: "npm",
	}}
}

func collectNPMDependency(packages *[]Package, seen map[string]struct{}, name string, dep npmDependency) {
	addNPMPackage(packages, seen, name, dep.Version)
	for childName, child := range dep.Dependencies {
		collectNPMDependency(packages, seen, childName, child)
	}
}

func addNPMPackage(packages *[]Package, seen map[string]struct{}, name string, version string) {
	if name == "" || version == "" {
		return
	}
	key := name + "\x00" + version
	if _, ok := seen[key]; ok {
		return
	}
	seen[key] = struct{}{}
	*packages = append(*packages, Package{
		Name:      name,
		Version:   version,
		Ecosystem: "npm",
	})
}

func npmPackageNameFromPath(path string) string {
	const marker = "node_modules/"
	index := strings.LastIndex(path, marker)
	if index == -1 {
		return ""
	}
	name := path[index+len(marker):]
	if strings.HasPrefix(name, "@") {
		parts := strings.SplitN(name, "/", 3)
		if len(parts) >= 2 {
			return parts[0] + "/" + parts[1]
		}
		return name
	}
	return strings.SplitN(name, "/", 2)[0]
}

func appendPackage(packages []Package, current Package, ecosystem string) ([]Package, Package) {
	if current.Name == "" || current.Version == "" {
		return packages, Package{}
	}
	current.Ecosystem = ecosystem
	return append(packages, current), Package{}
}
