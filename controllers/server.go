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

package controllers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/beego/beego/v2/server/web/pagination"
	"github.com/casdoor/casdoor/mcp"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/util"
)

// GetServers
// @Title GetServers
// @Tag Server API
// @Description get servers
// @Param   owner     query    string  true        "The owner of servers"
// @Success 200 {array} object.Server The Response object
// @router /get-servers [get]
func (c *ApiController) GetServers() {
	owner := c.Ctx.Input.Query("owner")
	if owner == "admin" {
		owner = ""
	}

	limit := c.Ctx.Input.Query("pageSize")
	page := c.Ctx.Input.Query("p")
	field := c.Ctx.Input.Query("field")
	value := c.Ctx.Input.Query("value")
	sortField := c.Ctx.Input.Query("sortField")
	sortOrder := c.Ctx.Input.Query("sortOrder")

	if limit == "" || page == "" {
		servers, err := object.GetServers(owner)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}
		c.ResponseOk(servers)
		return
	}

	limitInt := util.ParseInt(limit)
	count, err := object.GetServerCount(owner, field, value)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	paginator := pagination.SetPaginator(c.Ctx, limitInt, count)
	servers, err := object.GetPaginationServers(owner, paginator.Offset(), limitInt, field, value, sortField, sortOrder)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.ResponseOk(servers, paginator.Nums())
}

// GetServer
// @Title GetServer
// @Tag Server API
// @Description get server
// @Param   id     query    string  true        "The id ( owner/name ) of the server"
// @Success 200 {object} object.Server The Response object
// @router /get-server [get]
func (c *ApiController) GetServer() {
	id := c.Ctx.Input.Query("id")

	server, err := object.GetServer(id)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.ResponseOk(server)
}

// UpdateServer
// @Title UpdateServer
// @Tag Server API
// @Description update server
// @Param   id     query    string  true        "The id ( owner/name ) of the server"
// @Param   body    body   object.Server  true        "The details of the server"
// @Success 200 {object} controllers.Response The Response object
// @router /update-server [post]
func (c *ApiController) UpdateServer() {
	id := c.Ctx.Input.Query("id")

	var server object.Server
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &server)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.Data["json"] = wrapActionResponse(object.UpdateServer(id, &server))
	c.ServeJSON()
}

// AddServer
// @Title AddServer
// @Tag Server API
// @Description add server
// @Param   body    body   object.Server  true        "The details of the server"
// @Success 200 {object} controllers.Response The Response object
// @router /add-server [post]
func (c *ApiController) AddServer() {
	var server object.Server
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &server)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.Data["json"] = wrapActionResponse(object.AddServer(&server))
	c.ServeJSON()
}

// DeleteServer
// @Title DeleteServer
// @Tag Server API
// @Description delete server
// @Param   body    body   object.Server  true        "The details of the server"
// @Success 200 {object} controllers.Response The Response object
// @router /delete-server [post]
func (c *ApiController) DeleteServer() {
	var server object.Server
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &server)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.Data["json"] = wrapActionResponse(object.DeleteServer(&server))
	c.ServeJSON()
}

// ProxyServer
// @Title ProxyServer
// @Tag Server API
// @Description proxy request to the upstream MCP server by Server URL
// @Param   owner    path    string  true        "The owner name of the server"
// @Param   name     path    string  true        "The name of the server"
// @Success 200 {object} mcp.McpResponse The Response object
// @router /server/:owner/:name [post]
func (c *ApiController) ProxyServer() {
	owner := c.Ctx.Input.Param(":owner")
	name := c.Ctx.Input.Param(":name")

	var mcpReq *mcp.McpRequest
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &mcpReq)
	if err != nil {
		c.McpResponseError(1, -32700, "Parse error", err.Error())
		return
	}
	if util.IsStringsEmpty(owner, name) {
		c.McpResponseError(1, -32600, "invalid server identifier", nil)
		return
	}

	server, err := object.GetServer(util.GetId(owner, name))
	if err != nil {
		c.McpResponseError(mcpReq.ID, -32600, "server not found", err.Error())
		return
	}
	if server == nil {
		c.McpResponseError(mcpReq.ID, -32600, "server not found", nil)
		return
	}
	if server.Url == "" {
		c.McpResponseError(mcpReq.ID, -32600, "server URL is empty", nil)
		return
	}

	targetUrl, err := url.Parse(server.Url)
	if err != nil || !targetUrl.IsAbs() || targetUrl.Host == "" {
		c.McpResponseError(mcpReq.ID, -32600, "server URL is invalid", nil)
		return
	}
	if targetUrl.Scheme != "http" && targetUrl.Scheme != "https" {
		c.McpResponseError(mcpReq.ID, -32600, "server URL scheme is invalid", nil)
		return
	}

	if mcpReq.Method == "tools/call" {
		var params mcp.McpCallToolParams
		err = json.Unmarshal(mcpReq.Params, &params)
		if err != nil {
			c.McpResponseError(mcpReq.ID, -32600, "Invalid request", err.Error())
			return
		}

		for _, tool := range server.Tools {
			if tool.Name == params.Name && !tool.IsAllowed {
				c.McpResponseError(mcpReq.ID, -32600, "tool is forbidden", nil)
				return
			} else if tool.Name == params.Name {
				break
			}
		}
	}

	proxy := httputil.NewSingleHostReverseProxy(targetUrl)
	proxy.ErrorHandler = func(writer http.ResponseWriter, request *http.Request, proxyErr error) {
		c.Ctx.Output.SetStatus(http.StatusBadGateway)
		c.McpResponseError(mcpReq.ID, -32603, "failed to proxy server request: %s", proxyErr.Error())
	}
	proxy.Director = func(request *http.Request) {
		request.URL.Scheme = targetUrl.Scheme
		request.URL.Host = targetUrl.Host
		request.Host = targetUrl.Host
		request.URL.Path = targetUrl.Path
		request.URL.RawPath = ""
		request.URL.RawQuery = targetUrl.RawQuery

		if server.Token != "" {
			request.Header.Set("Authorization", "Bearer "+server.Token)
		}
	}

	proxy.ServeHTTP(c.Ctx.ResponseWriter, c.Ctx.Request)
}

// GetServerTools
// @Title GetServerTools
// @Tag Server API
// @Description get mcp server tool list
// @Param   id    query    string  true        "The owner name of the server"
// @Success 200 {object} controllers.Response The Response object
// @router /server/get-server-tools [get]
func (c *ApiController) GetServerTools() {
	id := c.Ctx.Input.Query("id")

	server, err := object.GetServer(id)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	if server == nil {
		c.ResponseError(fmt.Sprintf(c.T("server:Server %s not found"), id))
		return
	}

	tools, err := object.GetServerTools(server)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.ResponseOk(tools)
}
