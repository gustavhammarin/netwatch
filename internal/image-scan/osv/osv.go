package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"netwatch/internal/image-scan/parser"
)

func QueryOSV(pkg parser.Package) ([]Finding, error) {
	return QueryOSVContext(context.Background(), http.DefaultClient, pkg)
}

func QueryOSVContext(ctx context.Context, client *http.Client, pkg parser.Package) ([]Finding, error) {
	body, err := json.Marshal(OsvRequest{
		Package: struct {
			Name      string "json:\"name\""
			Ecosystem string "json:\"ecosystem\""
		}{Name: pkg.Name, Ecosystem: pkg.Ecosystem},
		Version: pkg.Version,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal osv request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.osv.dev/v1/query", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create osv request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("query osv: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("query osv: unexpected status %s", resp.Status)
	}

	var result osvResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode osv response: %w", err)
	}

	var findings []Finding
	for _, vuln := range result.Vulns {
		findings = append(findings, Finding{
			Package:       pkg,
			Vulnerability: vuln,
		})
	}

	return findings, nil
}
