package osv

import (
	"bytes"
	"encoding/json"
	"net/http"
	"netwatch/internal/image-scan/parser"
)


func QueryOSV(pkg parser.Package) ([]Finding, error) {
	body, _ := json.Marshal(OsvRequest{
		Package: struct {
			Name      string "json:\"name\""
			Ecosystem string "json:\"ecosystem\""
		}{Name: pkg.Name, Ecosystem: pkg.Ecosystem},
		Version: pkg.Version,
	})

	resp, err := http.Post("https://api.osv.dev/v1/query", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result osvResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	var findings []Finding
	for _, vuln := range result.Vulns {
		findings = append(findings, Finding{
			Package: pkg,
			Vulnerability: Vulnerability{
				ID: vuln.ID,
				Summary: vuln.Summary,
				Aliases: vuln.Aliases,
			},
		})
	}

	return findings, nil
}
