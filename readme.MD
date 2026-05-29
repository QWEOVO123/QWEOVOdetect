# QWEOVOdetect

QWEOVOdetect 是一个开源的 SOCKS5 代理审计与滥用检测系统，用来保护你的 Xray 不被乱用。它会安静地观察代理流量里的 HTTP Host、TLS / QUIC SNI、疑似 SS 加密隧道和 Trojan 特征，然后把结果整理到数据库和前端仪表盘里，像一个小小的值班猫猫，喵呜。

## 主要功能

- SOCKS5 TCP CONNECT 转发
- SOCKS5 UDP ASSOCIATE 原生 UDP 转发
- 可配置 SOCKS5 入站端口，每个端口独立统计
- SOCKS5 入站支持昵称、启用状态和用户名密码认证
- SOCKS5 入站支持热加载，新增、禁用、改端口、改认证后无需重启
- 支持 Proxy Protocol 获取真实客户端 IP
- HTTP Host 检测
- TLS SNI 检测和统计
- QUIC Initial SNI 检测和统计，并在前端标记为 QUIC
- 疑似 SS / 加密隧道检测
- Trojan 特征检测和高危目标入库
- 域名关键词封禁，可阻断 HTTP Host / TLS SNI / QUIC SNI 命中的连接
- 目标 IP 地址封禁，可阻断指定远端目标 IP
- 端口取证功能，可按时间把 TLS / QUIC SNI、Trojan、SS 命中写入 txt
- H2 / MySQL 数据库配置
- Vue3 前端仪表盘展示统计结果

## 项目结构

```text
QWEOVOdetect/
├─ src/main/java/org/detector/qweovodetect/
│  ├─ server/      # SOCKS5 服务、TCP relay、UDP relay
│  ├─ dpi/         # DPI 检测模块：HTTP、TLS SNI、QUIC SNI、SS、Trojan 等
│  ├─ stats/       # API、统计服务、取证、数据库实体与仓库
│  └─ config/      # 安全配置、数据库配置
├─ src/main/resources/
│  └─ application.yml
├─ qweovo-front/   # Vue3 前端项目
├─ data/           # H2 本地数据库默认目录
├─ forensics/      # 取证 txt 输出目录，运行时自动创建
├─ build.gradle
└─ gradlew.bat
```

## 后端模块说明

- `Socks5Server`：按 `cfg` 中的入站配置启动 SOCKS5 监听服务，并支持入站热加载。
- `Socks5Handler`：处理 SOCKS5 握手、用户名密码认证、CONNECT、UDP ASSOCIATE 和 Proxy Protocol。
- `RelayHandler`：TCP 双向转发，同时对客户端方向流量进行 DPI 和封禁判断。
- `UdpRelayHandler`：原生 UDP 转发，并对客户端方向 QUIC Initial 尝试解析 SNI。
- `DpiEngine`：HTTP Host、TLS SNI、SS 检测入口。
- `QuicSniDpiEngine`：QUIC Initial 解密与 SNI 提取。
- `TrojanDpiEngineAsync`：Trojan 特征检测模块。
- `StatsService`：负责检测结果入库和高危目标聚合。
- `BlockRuleService`：负责域名关键词和目标 IP 封禁规则的入库、缓存和匹配。
- `ForensicsService`：负责端口取证任务、定时停止和 txt 文件写入。

## 配置与首次启动

项目首次启动时会进入前端初始化流程，需要配置：

- 初始管理员用户名和密码
- 数据库类型，支持 H2 / MySQL
- API 监听端口
- SOCKS5 入站端口、昵称、启用状态和认证配置

运行目录下会创建 `cfg` 文件，使用 JSON 保存运行配置。首次配置保存后，无论选择 H2 还是 MySQL，都必须重启后端服务，避免运行态配置和落盘配置不一致。重启前前端会停留在等待重启页面，后端也会拒绝登录，乖乖等你重启，喵。

后期修改规则：

- 修改 SOCKS5 入站配置：热加载生效，不需要重启
- 修改 API 端口：需要重启
- 修改数据库配置：需要重启

不要提交真实运行环境的 `cfg`、数据库文件、账号密码、Token 或密钥。

## 数据库

项目支持 H2 文件数据库和 MySQL。MySQL 配置保存前会实际测试连接，地址、端口、库名、用户名或密码不对时不会写入配置。

主要数据表包括：

- `sni_logs`：HTTP / TLS / QUIC SNI 访问记录
- `ss_logs`：疑似 SS / 加密隧道记录
- `trojan_logs`：Trojan 命中记录
- `risk_targets`：高危目标地址
- `block_rules`：域名关键词和目标 IP 封禁规则

## 封禁系统

前端仪表盘提供两类封禁规则。

域名关键词封禁示例：

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

- HTTP Host 命中：关闭 TCP 连接，并尽量通过 RST 阻断
- TLS SNI 命中：关闭 TCP 连接，并尽量通过 RST 阻断
- QUIC SNI 命中：直接丢弃对应 UDP 包，不继续转发

目标 IP 封禁示例：

```text
8.8.8.8
```

这是封禁远端目标 IP，不是封禁客户端源 IP。TCP CONNECT 会在解析到目标远端 IP 后阻断，UDP relay 会在解析 SOCKS5 UDP 目标地址后丢弃命中的包。

规则会写入数据库，并在后端缓存，避免每个数据包都查询数据库。

## 取证功能

前端仪表盘提供端口取证面板。你可以选择一个入站端口、填写文件名、设置取证时长，例如 5 分钟。后端会在运行目录下创建：

```text
forensics/<自定义文件名>.txt
```

取证期间会按行写入：

- TLS SNI
- QUIC SNI
- Trojan 命中信息
- SS 命中信息

示例：

```text
2026-05-29 18:44:47 [TLS] port=19084 client=1.2.3.4 sni=example.com
2026-05-29 18:44:47 [QUIC] port=19084 client=1.2.3.4 target=8.8.8.8:443 sni=example.com
2026-05-29 18:44:47 [TROJAN] port=19084 client=1.2.3.4 target=8.8.8.8 upload=700 download=174
2026-05-29 18:44:47 [SS] port=19084 client=1.2.3.4 target=8.8.8.8
```

同一个端口同一时间只允许一个取证任务。到时间后会自动停止，也可以在前端手动停止。

## 前端

前端位于：

```text
qweovo-front/
```

主要展示：

- 可配置入站端口维度统计
- 客户端访问概览
- HTTP / TLS / QUIC SNI 统计
- QUIC 标记
- 加密隧道触发排行
- 高危 SS / Trojan 目标地址
- 域名关键词封禁规则管理
- 目标 IP 封禁规则管理
- 端口取证任务管理
- 账号设置、数据库设置和入站设置

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
SOCKS5: 由 cfg 中的入站配置决定，首次默认 1080
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

本项目偏向本地研究、检测与可视化用途。UDP 转发为 SOCKS5 原生 UDP relay；普通 UDP 包正常转发，QUIC Initial 会尝试解析 SNI 用于统计、封禁和取证。Trojan 检测作用于 TCP relay 流量。

如果需要获取真实 IP，需要自己对 Xray 核心进行魔改，在 Socks5 出站实现的 TCP 建立后、S5 协议握手前执行 Proxy Protocol 来透传用户真实 IP 地址。

## License

This project is licensed under the GNU Affero General Public License v3.0. See [LICENSE](LICENSE) for details.
