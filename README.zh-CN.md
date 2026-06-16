# QWEOVOdetect 中文文档

![QWEOVOdetect cover](docs/assets/qweovodetect-cover.png)

**QWEOVOdetect** 是一个开源的 SOCKS5 代理审计与滥用检测系统。它可以被动检测代理流量，提取 HTTP Host、TLS/QUIC SNI，识别疑似 Shadowsocks 加密隧道和 Trojan 协议特征，并通过 Vue 3 控制台展示统计结果、封禁规则和取证任务。

## 功能

### SOCKS5 代理

- 支持 TCP CONNECT 转发
- 支持 UDP ASSOCIATE 原生 UDP relay
- 支持多个入站端口，每个端口可单独配置昵称、启用状态和用户名/密码认证
- 支持热加载：新增、禁用或修改 SOCKS5 入站端口和认证配置时不需要重启后端
- 支持 Proxy Protocol，用于获取真实客户端 IP

### DPI 深度包检测

- 检测 HTTP Host
- 提取 TLS ClientHello 中的 SNI
- 提取 QUIC Initial 包中的 SNI，并在前端标记为 QUIC
- 检测疑似 Shadowsocks / 加密隧道行为
- 检测 Trojan 协议特征，并记录高风险目标地址

### 封禁功能

- 支持域名关键词封禁，例如封禁 `tiktok` 会匹配 `tiktok.com`、`api-tiktok.example.com` 等
- 支持目标 IP 封禁，封禁的是远程目标 IP，不是客户端源 IP
- TCP 命中后会尽量使用 RST 断开连接；QUIC 命中后会丢弃 UDP 包
- 支持同步/异步 DPI 模式切换；异步模式优先转发，命中后断开连接并临时封禁目标

### 取证功能

- 可以按入站端口开启取证
- 自动记录 TLS SNI、QUIC SNI、Trojan 命中和 SS 命中
- 输出到项目运行目录下的 `forensics/<文件名>.txt`
- 支持设置取证时长，到期自动停止，也可以手动停止
- 同一个端口同一时间只允许一个取证任务

### 前端管理面板

- Vue 3 前端
- 实时统计
- 按端口展示流量和客户端信息
- HTTP / TLS / QUIC SNI 排行
- 加密隧道触发排行
- 高风险 SS / Trojan 目标地址
- 域名关键词和目标 IP 封禁规则管理
- 取证任务管理
- 账号设置、数据库配置、入站端口配置和 DPI 模式切换

### 数据存储

- 默认支持 H2 文件数据库，适合本地或开发环境
- 支持 MySQL，保存配置前会校验连接是否可用

## 项目结构

```text
QWEOVOdetect/
├─ src/main/java/org/detector/qweovodetect/
│  ├─ server/          SOCKS5 服务、TCP relay、UDP relay
│  ├─ dpi/             DPI 检测引擎：HTTP、TLS SNI、QUIC SNI、SS、Trojan
│  ├─ stats/           REST API、统计服务、取证、数据库实体和仓库
│  └─ config/          安全配置、JWT、数据库配置
├─ src/main/resources/
│  └─ application.yml  Spring Boot 应用配置
├─ qweovo-front/       Vue 3 前端（Vite）
├─ docs/assets/        README 图片资源
├─ data/               默认 H2 数据库目录，运行时生成
├─ forensics/          取证文件输出目录，运行时生成
├─ build.gradle        Gradle 构建配置，Spring Boot 3.3，Java 21
└─ settings.gradle
```

## 快速启动

### 环境要求

- Java 21 或更高版本
- Node.js 18+ 和 npm
- MySQL 可选，默认可以使用 H2

### 首次启动

启动后端：

```powershell
cd <项目目录>
.\gradlew.bat bootRun
```

启动前端：

```powershell
cd <项目目录>\qweovo-front
npm install
npm run dev
```

打开：

```text
http://localhost:5173
```

首次启动时，前端会引导你配置：

- 管理员用户名和密码
- 数据库类型，H2 或 MySQL
- API 监听地址和端口
- SOCKS5 入站端口，包括端口号、昵称、启用状态和认证配置

保存首次配置后，必须重启后端。前端会显示等待重启页面，后端 API 也会拒绝登录，直到后端重启。这是为了保证运行时配置和外部 `cfg` 文件完全同步。

## 配置变更是否需要重启

| 变更内容 | 是否需要重启 |
|---|---|
| SOCKS5 入站端口、新增、禁用、改端口、改认证 | 不需要，支持热加载 |
| DPI 同步/异步模式 | 不需要，切换时会断开现有 TCP/UDP relay |
| API 监听地址或端口 | 需要 |
| 数据库类型或连接信息 | 需要 |

## 封禁规则

### 域名关键词封禁

域名关键词封禁会作用于 HTTP Host、TLS SNI 和 QUIC SNI。

例如规则 `tiktok` 会匹配：

- `tiktok.com`
- `tiktokwwqe.com`
- `api-tiktok.example.com`

命中后的处理方式：

- HTTP Host 命中：关闭 TCP 连接，尽量使用 RST
- TLS SNI 命中：关闭 TCP 连接，尽量使用 RST
- QUIC SNI 命中：丢弃 UDP 包，异步模式下会临时封禁同用户同目标

### 目标 IP 封禁

目标 IP 封禁作用于远程目标 IP，不是客户端源 IP。TCP CONNECT 会在解析目标后阻断；UDP relay 会在解析 SOCKS5 UDP 目标地址后丢包。

封禁规则存储在数据库中，并缓存在内存里，避免每个数据包都查询数据库。

## 取证

前端取证面板可以针对指定入站端口，在指定时间内把检测事件写入文件。

- 选择入站端口，填写输出文件名，并设置取证时长，例如 5 分钟
- 输出文件位于项目目录下的 `forensics/<文件名>.txt`
- 每个端口同一时间只能有一个取证任务
- 任务到期会自动停止，也可以手动停止

输出示例：

```text
2026-05-29 18:44:47 [TLS] port=19084 client=1.2.3.4 sni=example.com
2026-05-29 18:44:47 [QUIC] port=19084 client=1.2.3.4 target=8.8.8.8:443 sni=example.com
2026-05-29 18:44:47 [TROJAN] port=19084 client=1.2.3.4 target=8.8.8.8 upload=700 download=174
2026-05-29 18:44:47 [SS] port=19084 client=1.2.3.4 target=8.8.8.8
```

## 数据库表

| 表名 | 说明 |
|---|---|
| `sni_logs` | HTTP / TLS / QUIC SNI 访问记录 |
| `ss_logs` | 疑似 Shadowsocks / 加密隧道记录 |
| `trojan_logs` | Trojan 特征命中记录 |
| `risk_targets` | 聚合后的高风险目标地址 |
| `block_rules` | 域名关键词和目标 IP 封禁规则 |

## 构建

后端：

```powershell
.\gradlew.bat compileJava
.\gradlew.bat bootJar
```

前端：

```powershell
cd qweovo-front
npm run build
```

## 默认端口

| 服务 | 默认值 |
|---|---|
| SOCKS5 | 写在 `cfg` 中，首次默认是 `1080` |
| API | `127.0.0.1:8080` |
| 前端开发服务器 | `http://localhost:5173` |

## 注意事项

- 本项目主要用于本地研究、检测和可视化。
- UDP 转发使用 SOCKS5 原生 UDP relay。普通 UDP 包正常转发，QUIC Initial 包会被检测 SNI，用于统计、封禁和取证。
- Trojan 检测作用于 TCP relay 流量。
- 如果要获取真实客户端 IP，需要让 Xray core 在 SOCKS5 握手前发送 Proxy Protocol，这样后端才能透明获取真实客户端地址。

## 安全说明

不要把运行时 `cfg` 文件、数据库文件、账号密码、token 或密钥提交到版本控制里。

`.gitignore` 默认会排除：

- `cfg`
- `data/`
- `forensics/`

## 鸣谢

- How the Great Firewall of China Detects and Blocks Fully Encrypted Traffic: https://www.usenix.org/system/files/usenixsecurity23-wu-mingshi.pdf
- Trojan-Killer: [XTLS/Trojan-killer](https://github.com/XTLS/Trojan-killer)

## 许可证

本项目使用 **GNU Affero General Public License v3.0**，也就是 **AGPL-3.0** 开源许可证。完整内容见 [LICENSE](LICENSE)。
