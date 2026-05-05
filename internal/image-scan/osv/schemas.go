package osv

import "netwatch/internal/image-scan/parser"

type osvResponse struct {
    Vulns []struct {
        ID      string   `json:"id"`
        Summary string   `json:"summary"`
        Aliases []string `json:"aliases"`
    } `json:"vulns"`
}

type Vulnerability struct {
    ID       string   `json:"id"`
    Summary  string   `json:"summary"`
    Aliases  []string `json:"aliases"`
}

type OsvRequest struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Version string `json:"version"`
}

type Finding struct {
	Package parser.Package `json:"package"`
	Vulnerability Vulnerability `json:"vulnerability"`
}