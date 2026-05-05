package parser

import "strings"

type Package struct {
	Name string `json:"name"`
	Version string `json:"version"`
	Architecture string `json:"architecture"`
	Ecosystem string `json:"ecosystem"`
}

func ParseAlpine(content []byte) []Package{
	var packages []Package
	var current Package
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		if line == ""{
			if current.Name != "" {
				current.Ecosystem = "Alpine"
				packages = append(packages, current)
				current = Package{}
			}
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
	return packages
}