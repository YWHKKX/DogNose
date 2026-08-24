# DogNose

轻量级网络嗅探工具，基于 Go + gopacket 实现抓包，通过 Web 界面实时展示流量，类似精简版 Wireshark。

## 功能

- 自动或指定网卡抓包
- BPF 过滤器（默认 `tcp`）
- 协议解析：Ethernet / IPv4 / IPv6 / TCP / UDP / HTTP
- WebSocket 实时推送抓包数据
- Wireshark 风格的分层详情展示
- 可选保存 `.pcap` 文件

## 环境要求

- Go 1.24+
- [Npcap](https://nmap.org/npcap/)（Windows）或 libpcap（Linux/macOS）
- **管理员 / root 权限**（抓包需要）

## 快速开始

```bash
# 克隆项目
git clone https://github.com/YWHKKX/DogNose.git
cd DogNose

# 运行（需要管理员权限）
go run main.go
```

浏览器访问 [http://127.0.0.1:8080](http://127.0.0.1:8080)，点击「启动嗅探器」进入抓包页面。

## 配置

通过环境变量配置：

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `DOGNOSE_PORT` | `8080` | Web 服务端口 |
| `DOGNOSE_DEVICE` | 空（自动选择） | 网卡名称或描述 |
| `DOGNOSE_FILTER` | `tcp` | BPF 过滤表达式 |

示例：

```bash
# 指定网卡并过滤 HTTP 流量
set DOGNOSE_DEVICE=Intel(R) Wi-Fi 6 AX201 160MHz
set DOGNOSE_FILTER=tcp port 80 or tcp port 443
go run main.go
```

## API

| 路由 | 说明 |
|------|------|
| `GET /` | 首页 |
| `GET /sniffer` | 抓包查看器 |
| `GET /api/devices` | 返回可用网卡列表（JSON） |
| `WS /packets` | WebSocket 实时抓包数据 |

## 项目结构

```
DogNose/
├── main.go                 # 入口
├── common/
│   ├── config/             # 环境变量配置
│   ├── sniffer/            # 抓包与协议解析
│   ├── utils/              # 日志工具
│   └── web/                # HTTP / WebSocket 服务
└── templates/              # 前端页面
```

## 许可证

MIT
