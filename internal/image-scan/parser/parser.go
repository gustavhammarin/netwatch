package parser

import "strings"

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

func appendPackage(packages []Package, current Package, ecosystem string) ([]Package, Package) {
	if current.Name == "" || current.Version == "" {
		return packages, Package{}
	}
	current.Ecosystem = ecosystem
	return append(packages, current), Package{}
}
