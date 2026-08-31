# DogNose

轻量级网络嗅探工具，基于 Go + gopacket 实现抓包，通过 Web 界面实时展示流量，类似精简版 Wireshark。

## 功能

- 自动或指定网卡抓包，支持 BPF 过滤器
- 协议解析：Ethernet / ARP / IPv4 / IPv6 / ICMP / ICMPv6 / TCP（含 Flags）/ UDP / DNS / TLS（含 SNI）/ HTTP
- Capture Hub：单路抓包 + 多客户端 WebSocket 广播 + 环形缓冲（O(1) 写入）
- 运行时暂停 / 继续 / 清空 / 热更新 BPF 过滤器
- 流量分析：协议分布、Top Talkers、速率（pps）、慢客户端丢批计数
- 导出：单包 JSON、缓冲 JSON（可按协议过滤）、运行时启停 PCAP 录制
- 前端：协议 Chip 过滤、搜索、自动滚动开关、十六进制 Dump
- 优雅退出（Ctrl+C）
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
| `DOGNOSE_SAVE_PCAP` / `-save-pcap` | `false` | 启动时是否落盘 pcap |

## API

| 路由 | 方法 | 说明 |
|------|------|------|
| `/` | GET | 首页 |
| `/sniffer` | GET | 抓包查看器 |
| `/api/devices` | GET | 网卡列表 |
| `/api/status` | GET | 抓包状态、协议分布、Top Talkers |
| `/api/capture/pause` | POST | 暂停抓包 |
| `/api/capture/resume` | POST | 继续抓包 |
| `/api/capture/clear` | POST | 清空缓冲与计数 |
| `/api/filter` | GET/PUT | 查询 / 更新 BPF 过滤器 |
| `/api/packets/export` | GET | 导出缓冲 JSON（`?protocol=HTTP` 可选） |
| `/api/packets/{id}` | GET | 按 frame id 查询单包 |
| `/api/pcap/start` | POST | 开始录制 pcap 到 `saves/` |
| `/api/pcap/stop` | POST | 停止录制 |
| `/packets` | WS | 实时抓包（含 snapshot + 增量） |

### 更新过滤器示例

```bash
curl -X PUT http://127.0.0.1:8080/api/filter ^
  -H "Content-Type: application/json" ^
  -d "{\"filter\":\"tcp port 80 or udp port 53 or arp or icmp\"}"
```

### 导出缓冲

```bash
curl -o export.json "http://127.0.0.1:8080/api/packets/export?protocol=DNS"
```

## 项目结构

```
DogNose/
├── main.go
├── common/
│   ├── config/      # 环境变量 + CLI
│   ├── sniffer/     # Device / Hub / 协议解析 / 统计
│   ├── utils/       # 日志
│   └── web/         # HTTP + WebSocket
└── templates/       # 前端页面
```

## 许可证

MIT
