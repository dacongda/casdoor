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

import React from "react";
import {Link} from "react-router-dom";
import {Button, Modal, Select, Table} from "antd";
import moment from "moment";
import * as Setting from "./Setting";
import * as ServerBackend from "./backend/ServerBackend";
import i18next from "i18next";
import BaseListPage from "./BaseListPage";
import PopconfirmModal from "./common/modal/PopconfirmModal";

class ServerListPage extends BaseListPage {
  constructor(props) {
    super(props);
    this.state = {
      ...this.state,
      scanLoading: false,
      scanResult: null,
      scanServers: [],
      showScanModal: false,
      scanCidrs: ["127.0.0.1/32"],
      scanPorts: [3000, 8080, 80],
      scanPaths: ["/", "/mcp", "/sse", "/mcp/sse"],
    };
  }

  newServer() {
    const randomName = Setting.getRandomName();
    const owner = Setting.getRequestOrganization(this.props.account);
    return {
      owner: owner,
      name: `server_${randomName}`,
      createdTime: moment().format(),
      displayName: `New Server - ${randomName}`,
      url: "",
      application: "",
    };
  }

  addServer() {
    const newServer = this.newServer();
    ServerBackend.addServer(newServer)
      .then((res) => {
        if (res.status === "ok") {
          this.props.history.push({pathname: `/servers/${newServer.owner}/${newServer.name}`, mode: "add"});
          Setting.showMessage("success", i18next.t("general:Successfully added"));
        } else {
          Setting.showMessage("error", `${i18next.t("general:Failed to add")}: ${res.msg}`);
        }
      })
      .catch(error => {
        Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`);
      });
  }

  deleteServer(i) {
    ServerBackend.deleteServer(this.state.data[i])
      .then((res) => {
        if (res.status === "ok") {
          Setting.showMessage("success", i18next.t("general:Successfully deleted"));
          this.fetch({
            pagination: {
              ...this.state.pagination,
              current: this.state.pagination.current > 1 && this.state.data.length === 1 ? this.state.pagination.current - 1 : this.state.pagination.current,
            },
          });
        } else {
          Setting.showMessage("error", `${i18next.t("general:Failed to delete")}: ${res.msg}`);
        }
      })
      .catch(error => {
        Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`);
      });
  }

  fetch = (params = {}) => {
    const field = params.searchedColumn, value = params.searchText;
    const sortField = params.sortField, sortOrder = params.sortOrder;
    if (!params.pagination) {
      params.pagination = {current: 1, pageSize: 10};
    }

    this.setState({loading: true});
    ServerBackend.getServers(Setting.getRequestOrganization(this.props.account), params.pagination.current, params.pagination.pageSize, field, value, sortField, sortOrder)
      .then((res) => {
        this.setState({loading: false});
        if (res.status === "ok") {
          this.setState({
            data: res.data,
            pagination: {
              ...params.pagination,
              total: res.data2,
            },
            searchText: params.searchText,
            searchedColumn: params.searchedColumn,
          });
        } else {
          Setting.showMessage("error", `${i18next.t("general:Failed to get")}: ${res.msg}`);
        }
      });
  };

  scanIntranetServers = (scanRequest) => {
    this.setState({scanLoading: true});
    ServerBackend.syncIntranetServers(scanRequest)
      .then((res) => {
        this.setState({scanLoading: false});
        if (res.status === "ok") {
          const scanResult = res.data ?? {};
          const scanServers = scanResult.servers ?? [];
          this.setState({scanResult: scanResult, scanServers: scanServers});
          Setting.showMessage("success", `${i18next.t("general:Successfully got")}: ${scanServers.length} server(s)`);
        } else {
          Setting.showMessage("error", `${i18next.t("general:Failed to get")}: ${res.msg}`);
        }
      })
      .catch(error => {
        this.setState({scanLoading: false});
        Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`);
      });
  };

  openScanModal = () => {
    this.setState({showScanModal: true});
  };

  closeScanModal = () => {
    if (this.state.scanLoading) {
      return;
    }
    this.setState({showScanModal: false});
  };

  submitScan = () => {
    const cidr = this.state.scanCidrs
      .map(item => item.trim())
      .filter(item => item !== "");
    const ports = this.state.scanPorts
      .map(item => Number(item))
      .filter(item => Number.isInteger(item) && item > 0 && item <= 65535);
    const paths = this.state.scanPaths
      .map(item => item.trim())
      .filter(item => item !== "");

    if (cidr.length === 0) {
      Setting.showMessage("error", i18next.t("server:Please select at least one IP range"));
      return;
    }
    if (ports.length === 0) {
      Setting.showMessage("error", i18next.t("server:Please select at least one port"));
      return;
    }

    this.scanIntranetServers({cidr: cidr, ports: ports, paths: paths});
  };

  addScannedServer = (scanServer) => {
    const owner = Setting.getRequestOrganization(this.props.account);
    const randomName = Setting.getRandomName();
    const newServer = {
      owner: owner,
      name: `server_${randomName}`,
      createdTime: moment().format(),
      displayName: `Scanned MCP ${scanServer.host}:${scanServer.port}`,
      url: scanServer.url,
      application: "",
    };

    ServerBackend.addServer(newServer)
      .then((res) => {
        if (res.status === "ok") {
          Setting.showMessage("success", i18next.t("general:Successfully added"));
          const {pagination} = this.state;
          this.fetch({pagination});
        } else {
          Setting.showMessage("error", `${i18next.t("general:Failed to add")}: ${res.msg}`);
        }
      })
      .catch(error => {
        Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`);
      });
  };

  renderTable(servers) {
    const columns = [
      {
        title: i18next.t("general:Name"),
        dataIndex: "name",
        key: "name",
        width: "160px",
        sorter: true,
        ...this.getColumnSearchProps("name"),
        render: (text, record, index) => {
          return (
            <Link to={`/servers/${record.owner}/${text}`}>
              {text}
            </Link>
          );
        },
      },
      {
        title: i18next.t("general:Organization"),
        dataIndex: "owner",
        key: "owner",
        width: "130px",
        sorter: true,
        ...this.getColumnSearchProps("owner"),
      },
      {
        title: i18next.t("general:Created time"),
        dataIndex: "createdTime",
        key: "createdTime",
        width: "180px",
        sorter: true,
        render: (text, record, index) => {
          return Setting.getFormattedDate(text);
        },
      },
      {
        title: i18next.t("general:Display name"),
        dataIndex: "displayName",
        key: "displayName",
        sorter: true,
        ...this.getColumnSearchProps("displayName"),
      },
      {
        title: i18next.t("general:URL"),
        dataIndex: "url",
        key: "url",
        sorter: true,
        ...this.getColumnSearchProps("url"),
        render: (text) => {
          if (!text) {
            return null;
          }

          return (
            <a target="_blank" rel="noreferrer" href={text}>
              {Setting.getShortText(text, 40)}
            </a>
          );
        },
      },
      {
        title: i18next.t("general:Application"),
        dataIndex: "application",
        key: "application",
        width: "140px",
        sorter: true,
        ...this.getColumnSearchProps("application"),
      },
      {
        title: i18next.t("general:Action"),
        dataIndex: "op",
        key: "op",
        width: "180px",
        fixed: (Setting.isMobile()) ? false : "right",
        render: (text, record, index) => {
          return (
            <div>
              <Button style={{marginTop: "10px", marginBottom: "10px", marginRight: "10px"}} type="primary" onClick={() => this.props.history.push(`/servers/${record.owner}/${record.name}`)}>{i18next.t("general:Edit")}</Button>
              <PopconfirmModal title={i18next.t("general:Sure to delete") + `: ${record.name} ?`} onConfirm={() => this.deleteServer(index)}>
              </PopconfirmModal>
            </div>
          );
        },
      },
    ];

    const filteredColumns = Setting.filterTableColumns(columns, this.props.formItems ?? this.state.formItems);
    const paginationProps = {
      total: this.state.pagination.total,
      showQuickJumper: true,
      showSizeChanger: true,
      showTotal: () => i18next.t("general:{total} in total").replace("{total}", this.state.pagination.total),
    };

    const scanColumns = [
      {
        title: i18next.t("general:Host"),
        dataIndex: "host",
        key: "host",
        width: "140px",
      },
      {
        title: i18next.t("general:Port"),
        dataIndex: "port",
        key: "port",
        width: "90px",
      },
      {
        title: i18next.t("general:Path"),
        dataIndex: "path",
        key: "path",
        width: "120px",
      },
      {
        title: i18next.t("general:URL"),
        dataIndex: "url",
        key: "url",
        render: (text) => {
          if (!text) {
            return null;
          }

          return (
            <a target="_blank" rel="noreferrer" href={text}>
              {Setting.getShortText(text, 60)}
            </a>
          );
        },
      },
      {
        title: i18next.t("general:Action"),
        dataIndex: "scanOp",
        key: "scanOp",
        width: "120px",
        render: (_, record) => {
          return (
            <Button size="small" type="primary" onClick={() => this.addScannedServer(record)}>
              {i18next.t("general:Add")}
            </Button>
          );
        },
      },
    ];

    const scanCidrOptions = [
      {label: "127.0.0.1/32", value: "127.0.0.1/32"},
      {label: "10.0.0.0/24", value: "10.0.0.0/24"},
      {label: "172.16.0.0/24", value: "172.16.0.0/24"},
      {label: "192.168.1.0/24", value: "192.168.1.0/24"},
    ];
    const scanPortOptions = [
      {label: "80", value: 80},
      {label: "443", value: 443},
      {label: "3000", value: 3000},
      {label: "8080", value: 8080},
    ];
    const scanPathOptions = [
      {label: "/", value: "/"},
      {label: "/mcp", value: "/mcp"},
      {label: "/sse", value: "/sse"},
      {label: "/mcp/sse", value: "/mcp/sse"},
    ];

    return (
      <>
        <Table
          scroll={{x: "max-content"}}
          dataSource={servers}
          columns={filteredColumns}
          rowKey={record => `${record.owner}/${record.name}`}
          pagination={{...this.state.pagination, ...paginationProps}}
          loading={this.state.loading}
          onChange={this.handleTableChange}
          size="middle"
          bordered
          title={() => (
            <div>
              {i18next.t("server:Edit MCP Server")}&nbsp;&nbsp;&nbsp;&nbsp;
              <Button type="primary" size="small" onClick={() => this.addServer()}>{i18next.t("general:Add")}</Button>
            &nbsp;
              <Button size="small" onClick={this.openScanModal}>{i18next.t("server:Scan server")}</Button>
            &nbsp;
              <Button size="small" onClick={() => this.props.history.push("/server-store")}>{i18next.t("general:MCP Store")}</Button>
            </div>
          )}
        />

        <Modal
          title="Scan server"
          open={this.state.showScanModal}
          width={960}
          confirmLoading={this.state.scanLoading}
          onOk={this.submitScan}
          onCancel={this.closeScanModal}
          okText={i18next.t("general:Sync")}
        >
          <div style={{marginBottom: "12px"}}>IP range</div>
          <Select
            mode="tags"
            style={{width: "100%"}}
            value={this.state.scanCidrs}
            options={scanCidrOptions}
            onChange={(value) => this.setState({scanCidrs: value})}
            placeholder="Select or input CIDR/IP"
          />

          <div style={{marginTop: "16px", marginBottom: "12px"}}>Ports</div>
          <Select
            mode="tags"
            style={{width: "100%"}}
            value={this.state.scanPorts}
            options={scanPortOptions}
            onChange={(value) => this.setState({scanPorts: value})}
            placeholder="Select or input ports"
          />

          <div style={{marginTop: "16px", marginBottom: "12px"}}>Paths</div>
          <Select
            mode="tags"
            style={{width: "100%"}}
            value={this.state.scanPaths}
            options={scanPathOptions}
            onChange={(value) => this.setState({scanPaths: value})}
            placeholder="Select or input paths"
          />

          {this.state.scanResult !== null ? (
            <Table
              style={{marginTop: "16px"}}
              scroll={{x: "max-content", y: 320}}
              dataSource={this.state.scanServers}
              columns={scanColumns}
              rowKey={(record, index) => `${record.url}-${index}`}
              pagination={false}
              size="middle"
              bordered
              title={() => {
                return `Scanned hosts: ${this.state.scanResult?.scannedHosts ?? 0}, online hosts: ${this.state.scanResult?.onlineHosts?.length ?? 0}, found servers: ${this.state.scanServers.length}`;
              }}
            />
          ) : null}
        </Modal>
      </>
    );
  }
}

export default ServerListPage;
