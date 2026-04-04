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

package mcp

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/casdoor/casdoor/util"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/oauth2"
)

type InnerMcpServer struct {
	Host            string `json:"host"`
	Port            int    `json:"port"`
	Path            string `json:"path"`
	Url             string `json:"url"`
	ProtocolVersion string `json:"protocolVersion"`
	ServerName      string `json:"serverName"`
	ServerVersion   string `json:"serverVersion"`
}

type initializeResponse struct {
	JSONRPC string `json:"jsonrpc"`
	Result  struct {
		ProtocolVersion string `json:"protocolVersion"`
		ServerInfo      struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"serverInfo"`
	} `json:"result"`
	Error interface{} `json:"error"`
}

func GetServerTools(owner, name, url, token string) ([]*mcpsdk.Tool, error) {
	var session *mcpsdk.ClientSession
	var err error

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*10)
	defer cancel()
	client := mcpsdk.NewClient(&mcpsdk.Implementation{Name: util.GetId(owner, name), Version: "1.0.0"}, nil)
	if token != "" {
		httpClient := oauth2.NewClient(ctx, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token}))
		session, err = client.Connect(ctx, &mcpsdk.StreamableClientTransport{Endpoint: url, HTTPClient: httpClient}, nil)
	} else {
		session, err = client.Connect(ctx, &mcpsdk.StreamableClientTransport{Endpoint: url}, nil)
	}

	if err != nil {
		return nil, err
	}
	defer session.Close()

	toolResult, err := session.ListTools(ctx, nil)
	if err != nil {
		return nil, err
	}

	return toolResult.Tools, nil
}

func SanitizeScheme(scheme string) string {
	scheme = strings.ToLower(strings.TrimSpace(scheme))
	if scheme == "https" {
		return "https"
	}
	return "http"
}

func SanitizeTimeout(timeoutMs int, defaultTimeoutMs int, maxTimeoutMs int) time.Duration {
	if timeoutMs <= 0 {
		timeoutMs = defaultTimeoutMs
	}
	if timeoutMs > maxTimeoutMs {
		timeoutMs = maxTimeoutMs
	}
	return time.Duration(timeoutMs) * time.Millisecond
}

func SanitizeConcurrency(maxConcurrency int, defaultConcurrency int, maxAllowed int) int {
	if maxConcurrency <= 0 {
		maxConcurrency = defaultConcurrency
	}
	if maxConcurrency > maxAllowed {
		maxConcurrency = maxAllowed
	}
	return maxConcurrency
}

func SanitizePorts(ports []int, defaultPorts []int) []int {
	if len(ports) == 0 {
		return append([]int{}, defaultPorts...)
	}

	portSet := map[int]struct{}{}
	result := make([]int, 0, len(ports))
	for _, port := range ports {
		if port <= 0 || port > 65535 {
			continue
		}
		if _, ok := portSet[port]; ok {
			continue
		}
		portSet[port] = struct{}{}
		result = append(result, port)
	}
	if len(result) == 0 {
		return append([]int{}, defaultPorts...)
	}
	return result
}

func SanitizePaths(paths []string, defaultPaths []string) []string {
	if len(paths) == 0 {
		return append([]string{}, defaultPaths...)
	}

	pathSet := map[string]struct{}{}
	result := make([]string, 0, len(paths))
	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		if _, ok := pathSet[path]; ok {
			continue
		}
		pathSet[path] = struct{}{}
		result = append(result, path)
	}
	if len(result) == 0 {
		return append([]string{}, defaultPaths...)
	}
	return result
}

func ParseCIDRHosts(cidr string, maxHosts int) ([]net.IP, error) {
	baseIp, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	ipv4 := baseIp.To4()
	if ipv4 == nil {
		return nil, fmt.Errorf("only IPv4 CIDR is supported")
	}
	if !util.IsIntranetIp(ipv4.String()) {
		return nil, fmt.Errorf("cidr must be intranet: %s", cidr)
	}

	ones, bits := ipNet.Mask.Size()
	hostBits := bits - ones
	if hostBits < 0 {
		return nil, fmt.Errorf("invalid cidr mask: %s", cidr)
	}

	if hostBits >= 63 {
		return nil, fmt.Errorf("cidr range is too large")
	}
	total := uint64(1) << hostBits
	if total > uint64(maxHosts)+2 {
		return nil, fmt.Errorf("cidr range is too large, max %d hosts", maxHosts)
	}

	start := binary.BigEndian.Uint32(ipv4.Mask(ipNet.Mask))
	end := start + uint32(total) - 1

	hosts := make([]net.IP, 0, total)
	for value := start; value <= end; value++ {
		if total > 2 && (value == start || value == end) {
			continue
		}

		candidate := make(net.IP, net.IPv4len)
		binary.BigEndian.PutUint32(candidate, value)
		if ipNet.Contains(candidate) {
			hosts = append(hosts, candidate)
		}
	}

	if len(hosts) == 0 {
		return nil, fmt.Errorf("cidr has no usable hosts: %s", cidr)
	}

	return hosts, nil
}

func ProbeHost(ctx context.Context, client *http.Client, scheme, host string, ports []int, paths []string, token string, timeout time.Duration) (bool, []*InnerMcpServer) {
	dialer := &net.Dialer{Timeout: timeout}
	isOnline := false
	servers := []*InnerMcpServer{}

	for _, port := range ports {
		address := net.JoinHostPort(host, strconv.Itoa(port))
		conn, err := dialer.DialContext(ctx, "tcp", address)
		if err != nil {
			continue
		}
		_ = conn.Close()
		isOnline = true

		for _, path := range paths {
			server, ok := probeMcpInitialize(ctx, client, scheme, host, port, path, token)
			if ok {
				servers = append(servers, server)
			}
		}
	}

	return isOnline, servers
}

func probeMcpInitialize(ctx context.Context, client *http.Client, scheme, host string, port int, path, token string) (*InnerMcpServer, bool) {
	fullUrl := fmt.Sprintf("%s://%s%s", scheme, net.JoinHostPort(host, strconv.Itoa(port)), path)

	payload := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]interface{}{},
			"clientInfo": map[string]interface{}{
				"name":    "Casdoor Sync",
				"version": "1.0.0",
			},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, false
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, fullUrl, bytes.NewReader(body))
	if err != nil {
		return nil, false
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	if token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, false
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, false
	}

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, false
	}

	var initResp initializeResponse
	if err = json.Unmarshal(respBody, &initResp); err != nil {
		return nil, false
	}

	if initResp.JSONRPC != "2.0" || initResp.Error != nil {
		return nil, false
	}
	if initResp.Result.ProtocolVersion == "" && initResp.Result.ServerInfo.Name == "" {
		return nil, false
	}

	return &InnerMcpServer{
		Host:            host,
		Port:            port,
		Path:            path,
		Url:             fullUrl,
		ProtocolVersion: initResp.Result.ProtocolVersion,
		ServerName:      initResp.Result.ServerInfo.Name,
		ServerVersion:   initResp.Result.ServerInfo.Version,
	}, true
}
