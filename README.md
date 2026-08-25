# DogNose

轻量级网络嗅探工具，基于 Go + gopacket 实现抓包，通过 Web 界面实时展示流量，类似精简版 Wireshark。

## 功能

- 自动或指定网卡抓包，支持 BPF 过滤器
- 协议解析：Ethernet / IPv4 / IPv6 / TCP（含 Flags）/ UDP / DNS / TLS（含 SNI）/ HTTP
- Capture Hub：单路抓包 + 多客户端 WebSocket 广播 + 环形缓冲
- 运行时暂停 / 继续 / 清空 / 热更新 BPF 过滤器
- 统计面板：包数、缓冲、流量、连接状态
- 导出选中数据包为 JSON
- 可选保存 `.pcap` 到 `saves/`
- 支持环境变量与命令行参数

## 环境要求

- Go 1.24+
- [Npcap](https://nmap.org/npcap/)（Windows）或 libpcap（Linux/macOS）
- **管理员 / root 权限**（抓包需要）

## 快速开始

```bash
git clone https://github.com/YWHKKX/DogNose.git
cd DogNose

# 需要管理员权限
go run .

# 或指定参数
go run . -port 8080 -filter "tcp or udp" -device "Intel(R) Wi-Fi"
```

浏览器访问 [http://127.0.0.1:8080](http://127.0.0.1:8080)，进入「嗅探器」页面。

## 配置

环境变量与 CLI 均可（CLI 优先）：

| 变量 / 参数 | 默认值 | 说明 |
|-------------|--------|------|
| `DOGNOSE_PORT` / `-port` | `8080` | Web 服务端口 |
| `DOGNOSE_DEVICE` / `-device` | 空（自动选择） | 网卡名称或描述 |
| `DOGNOSE_FILTER` / `-filter` | `tcp or udp` | BPF 过滤表达式 |
| `DOGNOSE_SNAPSHOT` / `-snapshot` | `65535` | 抓包子节长度 |
| `DOGNOSE_PROMISCUOUS` / `-promiscuous` | `false` | 混杂模式 |
| `DOGNOSE_BUFFER` / `-buffer` | `2000` | 内存环形缓冲包数 |
| `DOGNOSE_SAVE_PCAP` / `-save-pcap` | `false` | 是否落盘 pcap |

## API

| 路由 | 方法 | 说明 |
|------|------|------|
| `/` | GET | 首页 |
| `/sniffer` | GET | 抓包查看器 |
| `/api/devices` | GET | 网卡列表 |
| `/api/status` | GET | 抓包状态与统计 |
| `/api/capture/pause` | POST | 暂停抓包 |
| `/api/capture/resume` | POST | 继续抓包 |
| `/api/capture/clear` | POST | 清空缓冲与计数 |
| `/api/filter` | GET/PUT | 查询 / 更新 BPF 过滤器 |
| `/packets` | WS | 实时抓包（含 snapshot + 增量） |

### 更新过滤器示例

```bash
curl -X PUT http://127.0.0.1:8080/api/filter ^
  -H "Content-Type: application/json" ^
  -d "{\"filter\":\"tcp port 80 or udp port 53\"}"
```

## 项目结构

```
DogNose/
├── main.go
├── common/
│   ├── config/      # 环境变量 + CLI
│   ├── sniffer/     # Device / Hub / 协议解析
│   ├── utils/       # 日志
│   └── web/         # HTTP + WebSocket
└── templates/       # 前端页面
```

## 许可证

MIT
