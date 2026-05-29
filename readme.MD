# QWEOVOdetect

QWEOVOdetect - 开源的 SOCKS5 代理审计与滥用检测系统，保护你的Xray不被滥用

## 主要功能

- SOCKS5 TCP CONNECT 转发
- SOCKS5 UDP ASSOCIATE 原生 UDP 转发
- 1080-1090 多端口监听，每个端口独立统计
- 支持 Proxy Protocol 获取真实客户端 IP
- HTTP Host 检测
- TLS SNI 检测和统计
- QUIC Initial SNI 检测和统计，并在前端标记为 QUIC
- 疑似 SS / 加密隧道检测
- Trojan 特征检测和高危目标入库
- 域名关键词封禁，可阻断 HTTP Host / TLS SNI / QUIC SNI 命中的连接
- H2 / MySQL 数据库配置
- Vue3 前端仪表盘展示统计结果

## 项目结构

```text
QWEOVOdetect/
├─ src/main/java/org/detector/qweovodetect/
│  ├─ server/      # SOCKS5 服务、TCP relay、UDP relay
│  ├─ dpi/         # DPI 检测模块：HTTP、TLS SNI、QUIC SNI、SS、Trojan 等
│  ├─ stats/       # API、统计服务、数据库实体与仓库
│  └─ config/      # 安全配置、数据库配置
├─ src/main/resources/
│  └─ application.yml
├─ qweovo-front/   # Vue3 前端项目
├─ data/           # H2 本地数据库默认目录
├─ build.gradle
└─ gradlew.bat
```

## 后端模块说明

- `Socks5Server`：启动 SOCKS5 监听服务，默认监听 `1080-1090`。
- `Socks5Handler`：处理 SOCKS5 握手、CONNECT、UDP ASSOCIATE 和 Proxy Protocol。
- `RelayHandler`：TCP 双向转发，同时对客户端方向流量进行 DPI 和封禁判断。
- `UdpRelayHandler`：原生 UDP 转发，并对客户端方向 QUIC Initial 尝试解析 SNI。
- `DpiEngine`：HTTP Host、TLS SNI、SS 检测入口。
- `QuicSniDpiEngine`：QUIC Initial 解密与 SNI 提取。
- `TrojanDpiEngineAsync`：Trojan 特征检测模块。
- `StatsService`：负责检测结果入库和高危目标聚合。
- `BlockRuleService`：负责域名关键词封禁规则的入库、缓存和匹配。

## 数据库

项目支持 H2 文件数据库和 MySQL。首次启动时会进入前端配置流程，需要手动设置初始用户名、密码，并选择 H2 或 MySQL 数据库。

运行目录下会创建 `cfg` 文件，使用 JSON 保存：

- 首次启动状态
- 登录用户名和密码哈希
- 数据库类型和连接配置

主要数据表包括：

- `sni_logs`：HTTP / TLS / QUIC SNI 访问记录
- `ss_logs`：疑似 SS / 加密隧道记录
- `trojan_logs`：Trojan 命中记录
- `risk_targets`：高危目标地址
- `block_rules`：域名关键词封禁规则

不要提交真实运行环境的 `cfg`、数据库文件、账号密码、Token 或密钥。

## 封禁系统

前端仪表盘提供“域名关键词封禁”输入框。输入关键词后，后续检测到的域名只要包含该关键词就会触发封禁。

示例：

```text
tiktok
```

可以命中：

```text
tiktok.com
tiktokwwqe.com
api-tiktok.example
```

阻断方式：

- HTTP Host 命中：关闭 TCP 连接，并尽量通过 RST 阻断。
- TLS SNI 命中：关闭 TCP 连接，并尽量通过 RST 阻断。
- QUIC SNI 命中：直接丢弃对应 UDP 包，不继续转发。

规则会写入数据库，并在后端缓存，避免每个数据包都查询数据库。

## 前端

前端位于：

```text
qweovo-front/
```

主要展示：

- 1080-1090 端口维度统计
- 客户端访问概览
- HTTP / TLS / QUIC SNI 统计
- QUIC 标记
- 加密隧道触发排行
- 高危 SS / Trojan 目标地址
- 域名关键词封禁规则管理
- 账号设置和数据库设置

## 运行方式

启动后端：

```powershell
cd <项目目录>
.\gradlew.bat bootRun
```

启动前端：

```powershell
cd <项目目录>\qweovo-front
npm.cmd run dev
```

前端默认访问：

```text
http://localhost:5173
```

后端默认监听：

```text
SOCKS5: 127.0.0.1:1080-1090
API:    127.0.0.1:8080
```

## 构建

后端编译：

```powershell
.\gradlew.bat compileJava
```

后端打包：

```powershell
.\gradlew.bat bootJar
```

前端构建：

```powershell
cd qweovo-front
npm.cmd run build
```

## 说明

本项目偏向本地研究、检测与可视化用途。UDP 转发为 SOCKS5 原生 UDP relay；普通 UDP 包正常转发，QUIC Initial 会尝试解析 SNI 用于统计和封禁。Trojan 检测作用于 TCP relay 流量。
如果需要获取真实IP，需要自己对Xray核心进行魔改，在Socks5出站实现的tcp建立后S5协议握手前执行proxy protocol来透传用户真实IP地址

## License

This project is licensed under the GNU Affero General Public License v3.0. See [LICENSE](LICENSE) for details.
