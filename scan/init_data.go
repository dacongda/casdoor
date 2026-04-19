// Copyright 2026 The Casdoor Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package scan

import (
	"strings"

	"github.com/beego/beego/v2/core/logs"
)

const dataSourceUrl = "https://casdoor.ai/casdoor-data/data.json"

func init() {
	setScanLists(map[string][]CVE{}, []Fingerprint{})

	go func() {
		cves, fingerprints, err := getOnlineScanLists(dataSourceUrl)
		if err != nil {
			logs.Warning("scan: failed to initialize scan lists from %s: %v", dataSourceUrl, err)
			return
		}

		setScanLists(buildCVEMap(cves), buildFingerprintList(fingerprints))
	}()
}

func buildCVEMap(cves []CVE) map[string][]CVE {
	cveMap := make(map[string][]CVE)
	for _, cve := range cves {
		name := strings.TrimSpace(cve.Name)
		if name == "" {
			continue
		}

		cveMap[name] = append(cveMap[name], cve)
	}

	return cveMap
}

func buildFingerprintList(fingerprints []Fingerprint) []Fingerprint {
	result := make([]Fingerprint, 0, len(fingerprints))
	for _, fingerprint := range fingerprints {
		if strings.TrimSpace(fingerprint.Name) == "" {
			continue
		}

		result = append(result, fingerprint)
	}

	return result
}
