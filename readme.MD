# QWEOVOdetect

QWEOVOdetect 是一个本地 SOCKS5 / DPI 流量检测项目，用来观察代理流量中的 SNI、疑似加密隧道、Trojan 特征流量，并把检测结果保存到 H2 数据库，再通过 Vue 前端展示。

## 主要功能

- SOCKS5 TCP CONNECT 转发
- SOCKS5 UDP ASSOCIATE 原生 UDP 转发
- TLS SNI 解析与访问统计
- 疑似 SS / 加密隧道检测
- Trojan 特征检测
- 高危目标地址标记
- H2 本地数据库持久化
- Vue 仪表盘展示统计结果

## 项目结构

```text
QWEOVOdetect/
├─ src/main/java/org/detector/qweovodetect/
│  ├─ server/      # SOCKS5 服务、TCP relay、UDP relay
│  ├─ dpi/         # DPI 检测模块：SNI、SS、Trojan 等
│  ├─ stats/       # API、统计服务、数据库实体与仓库
│  └─ config/      # 登录认证、JWT、安全配置
├─ src/main/resources/
│  ├─ application.yml
│  └─ templates/
├─ qweovo-front/   # Vue 前端项目
├─ data/           # H2 数据库文件目录
├─ build.gradle
└─ gradlew.bat
```

## 后端模块说明

- `Socks5Server`：启动 SOCKS5 监听服务，默认端口 `1080`。
- `Socks5Handler`：处理 SOCKS5 握手、CONNECT、UDP ASSOCIATE。
- `RelayHandler`：TCP 双向转发，同时把 TCP 数据喂给 DPI 模块。
- `UdpRelayHandler`：原生 UDP 转发，不参与 DPI 检测。
- `DpiEngine`：常规 DPI 入口，主要处理 SNI / SS 检测。
- `TrojanDpiEngineAsync`：独立 Trojan 检测模块，按连接维护双向状态。
- `StatsService`：负责检测结果入库和高危目标聚合。

## 数据库

项目使用 H2 文件数据库，配置在：

```text
src/main/resources/application.yml
```

默认数据库路径：

```text
./data/socks5_stats
```

主要数据包括：

- `sni_logs`：SNI 访问记录
- `ss_logs`：疑似 SS / 加密隧道记录
- `trojan_logs`：Trojan 命中记录
- `risk_targets`：高危目标地址

## 前端

前端位于：

```text
qweovo-front/
```

主要页面是 Vue 仪表盘，用来展示：

- 客户端访问概况
- TLS / SNI 统计
- 加密隧道触发排行
- 高危 SS / Trojan 目标地址
- 来源客户端信息

## 运行方式

启动后端：

```powershell
.\gradlew.bat bootRun
```

启动前端：

```powershell
npm.cmd run dev
```

前端默认访问：

```text
http://localhost:5173
```

后端默认监听：

```text
SOCKS5: 127.0.0.1:1080
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

本项目偏向本地研究、检测与可视化用途。UDP 转发只做原生 SOCKS5 UDP relay，不进入 DPI；Trojan 检测只作用于 TCP relay 流量。
