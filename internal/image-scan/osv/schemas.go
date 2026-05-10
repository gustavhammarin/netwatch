package osv

import (
	"encoding/json"
	"netwatch/internal/image-scan/parser"
)

type osvResponse struct {
	Vulns []json.RawMessage `json:"vulns"`
}

type OsvRequest struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Version string `json:"version"`
}

type Finding struct {
	Package       parser.Package  `json:"package"`
	Vulnerability json.RawMessage `json:"vulnerability"`
}
