# lightweight-ip-traffic-sa

![Go](https://img.shields.io/badge/Go-1.24.x-00ADD8?logo=go)![Vue](https://img.shields.io/badge/Vue-3-42b883?logo=vue.js)![Vite](https://img.shields.io/badge/Vite-6-646cff?logo=vite)![Gin](https://img.shields.io/badge/Gin-API-008ecf)![Status](https://img.shields.io/badge/Status-Demoable-success)![Phase](https://img.shields.io/badge/Phase-5%20in%20progress-orange)



一个面向 IP 多特征融合的轻量化态势感知系统。项目当前已打通“登录鉴权 -> 安全任务 -> 特征采集与评分 -> 总览展示 -> 预警与记录 -> 安全配置”的主链路，并在此基础上接入了基于 `gopacket` 的流量增强链路，支持离线 `pcap/pcapng` 深度解析、短时在线抓包、流量落库、任务级证据回溯与趋势展示。

当前仓库不是空白骨架，而是一个已经可运行、可演示、可继续扩展的前后端分离项目。

## 目录

- [项目概览](#项目概览)
- [核心能力](#核心能力)
- [当前状态](#当前状态)
- [技术栈](#技术栈)
- [项目结构](#项目结构)
- [快速开始](#快速开始)
- [配置说明](#配置说明)
- [默认账号与权限](#默认账号与权限)
- [关键页面与接口](#关键页面与接口)
- [数据源与流量模式](#数据源与流量模式)

## 项目概览

本项目围绕“IP 静态画像 + 流量动态特征 + 风险评分 + 证据解释”展开，采用 `system + security` 双域结构组织前后端代码：

- `system`：登录、登出、当前用户、用户管理、操作审计
- `security`：态势总览、安全任务、历史记录、预警中心、安全配置、实时流量监控

当前形成了两条并行但边界清晰的业务链路：

- 默认业务主链：`GeoLite2 Country / City / ASN + RDAP fallback + local blacklist / CIDR + limited-port-scan`
- 流量增强主链：`gopacket + offline_pcap / online_capture + sec_flow_* 三表 + 页面承接链路`

其中流量能力目前定位为“增强主链”，不作为所有任务的默认前置条件，也不污染默认业务主链的来源覆盖统计。

## 核心能力

### 1. 主链路业务能力

- JWT 登录鉴权与角色权限控制
- 安全任务创建、列表、详情、删除
- IP 基础画像、信誉特征、攻击面特征采集
- 风险评分、风险等级、评分因子和联合判定说明
- 总览趋势、历史记录、预警中心、安全配置
- 用户管理与系统操作审计

### 2. 流量增强能力

- `offline_pcap`：真实解析 `pcap/pcapng`，并落库到流量三表
- `online_capture`：基于 `Npcap SDK + gopacket/pcap` 的短时在线抓包
- 任务详情支持展示单任务下的多次流量采集历史
- 总览支持流量趋势与地理风险热力图
- 任务级 IP-流量关联图谱查询
- 配置页支持在线抓包网卡枚举与流量开关控制

### 3. 动态特征与证据字段

当前已稳定接入的流量增强字段包括：

- `dnsTopQuestions`
- `httpHostHints`
- `httpMethodHints`
- `tlsHandshakeHints`
- `applicationSignals`
- `directionalityIndicators`
- `portDensityIndicators`
- `payloadEntropyIndicators`

同时风险评分已显式区分：

- `baseScore`
- `reputationScore`
- `attackSurfaceScore`
- `behaviorScore`
- `ruleAdjustmentValue`
- `algorithmVersion`
- `weightProfile`

## 当前状态


### 当前可明确确认的工程状态

- 项目主链路稳定，可本地演示
- `GeoLite2 + RDAP` 已成为基础画像默认口径
- `RDAP` 已支持主端点 + 备用端点轮询 fallback
- 本地 `mmdb` 缺失时，系统会降级为“部分字段缺失但不阻断任务主链路”
- `gopacket` 已真实进入离线流量解析链路
- `online_capture` 已切换为短时真实抓包路线
- `sec_flow_collection / sec_flow_window_aggregate / sec_flow_feature_snapshot` 已落地
- 安全配置页已支持邮件预警相关字段与流量网卡枚举接口
- 实时流量监控页、地理风险热力图、任务关系图、操作审计页均已接入

## 技术栈

### 后端

- Go `1.24.x`
- Gin
- Gorm
- MySQL
- Redis
- JWT
- YAML 配置
- `gopacket`

### 前端

- Vue 3
- Vite
- Vue Router
- Pinia
- Axios
- Element Plus
- ECharts
- `vue-echarts`

## 项目结构

```text
lightweight-ip-traffic-sa/
├─ server/                 # Go 后端
│  ├─ api/v1/              # API 入口
│  ├─ service/             # 业务服务
│  ├─ router/              # 路由注册
│  ├─ model/               # 数据模型
│  ├─ repository/          # 数据访问
│  ├─ initialize/          # 初始化与启动
│  ├─ data/                # 本地数据源目录
│  ├─ demo_schema.sql      # 数据库初始化脚本
│  └─ demo_seed.sql        # 演示数据脚本
├─ web/                    # Vue 前端
│  ├─ src/api/             # 接口封装
│  ├─ src/router/          # 路由
│  ├─ src/pinia/           # 状态管理
│  ├─ src/view/security/   # 安全域页面
│  └─ src/view/system/     # 系统域页面
├─ docs/                   # 架构、进度、接口与阶段文档
├─ tests/                  # 验证资产与性能脚本骨架
├─ deliverables/           # 交付目录骨架
└─ README.md
```

## 快速开始

### 运行环境

基础运行环境：

- Go `1.24.x`
- Node.js `22.x` 或兼容版本
- npm `10+`
- MySQL `8.0+`
- Redis `6.x / 7.x`

安全能力相关环境：

| 环境 / 数据源 | 用途 | 是否必需 | 缺失或不可用时的行为 |
| --- | --- | --- | --- |
| `GeoLite2-Country.mmdb` / `GeoLite2-City.mmdb` / `GeoLite2-ASN.mmdb` | 本地 IP 国家、城市、ASN 与组织画像 | 推荐准备，非启动硬依赖 | 基础画像记录降级原因，并回退到 `RDAP` 或保留部分字段缺失 |
| RDAP 公网访问 | 补充 IP 注册组织、网段、联系人等注册信息 | 非启动硬依赖 | 请求失败时记录降级原因，不阻断任务主链路 |
| `server/data/security/local-blacklist.txt` | 本地黑名单 / CIDR 信誉来源 | 推荐准备，非启动硬依赖 | 文件缺失或未命中时走默认信誉分或降级证据 |
| Nmap | 攻击面增强能力，读取 `security.source.attackSurface.nmapPath`，默认命令名为 `nmap` | 可选 | 未安装、关闭或执行失败时回退到 Go 原生 `limited-port-scan` |
| Npcap / Npcap SDK | `online_capture`、实时流量监控和网卡枚举；配合 `gopacket/pcap` 使用 | 仅在线抓包 / 实时监控必需 | 网卡不可用、权限不足或 Npcap 不可用时记录失败状态，不阻断默认 IP 检测任务 |
| pcap / pcapng 文件 | `offline_pcap` 离线流量解析输入 | 仅离线流量解析必需 | 未配置、不可读或解析失败时只保留流量失败说明，不阻断默认 IP 检测任务 |

Windows 环境启用 `online_capture` 或 `/security/monitor` 时，建议安装 Npcap 并以管理员权限运行后端，确保网卡能被 Npcap 暴露。需要使用 Nmap 增强时，请安装 Nmap 并将其加入 `PATH`，或把 `security.source.attackSurface.nmapPath` 配置为可执行文件的完整路径。

### 1. 初始化数据库

先创建数据库：

```sql
CREATE DATABASE IF NOT EXISTS light_situation_awareness
DEFAULT CHARACTER SET utf8mb4
DEFAULT COLLATE utf8mb4_general_ci;
```

再执行：

- `server/demo_schema.sql`
- 可选：`server/demo_seed.sql`

说明：

- 仅验证结构和最小启动链路时，只执行 `demo_schema.sql` 即可
- 需要快速展示任务、总览、预警、历史、流量样例时，建议同时执行 `demo_seed.sql`

### 2. 准备后端配置

复制配置模板：

```powershell
Copy-Item .\server\config_example.yaml .\server\config.yaml
```

至少需要确认以下配置：

- `database.dsn`
- `redis.enabled`
- `redis.addr`
- `security.demoMode`
- `security.source.geoLite2.*`
- `security.source.rdap.*`
- `security.source.attackSurface.*`
- `security.source.flow.*`

如果要启用本地 `GeoLite2`，请准备以下文件：

- `server/data/geoip/GeoLite2-Country.mmdb`
- `server/data/geoip/GeoLite2-City.mmdb`
- `server/data/geoip/GeoLite2-ASN.mmdb`

这些路径默认按后端工作目录 `server/` 解析。也就是说，默认配置 `data/geoip/GeoLite2-City.mmdb` 实际对应 `server/data/geoip/GeoLite2-City.mmdb`。如果不放置本地 `mmdb` 文件，系统仍可运行，但画像会按降级口径回退到 `RDAP` 或部分字段缺失。

如果要启用 Nmap 增强，请确认：

- `security.source.attackSurface.nmapEnabled=true`
- `security.source.attackSurface.nmapPath` 能被后端进程执行
- 当前主机允许对目标 IP 执行受控端口探测

如果要启用流量能力，请按模式补齐配置：

- `sample`：样本画像模式，不需要真实抓包环境
- `offline_pcap`：配置 `security.source.flow.pcapFilePath`，并确保后端进程可读取该 `pcap/pcapng` 文件
- `online_capture`：配置 `security.source.flow.interfaceName`，并确保 Npcap、网卡和管理员权限可用

### 3. 启动后端

```powershell
cd .\server
go mod tidy
go run main.go
```

默认监听：

- `http://127.0.0.1:8080`

后端入口：

- `server/main.go`
- `server/initialize/router.go`

### 4. 启动前端

```powershell
cd .\web
npm install
npm run dev
```

默认地址：

- `http://127.0.0.1:5173`

开发代理：

- `/api/* -> http://127.0.0.1:8080`

## 配置说明

### 配置文件

- 实际读取：`server/config.yaml`
- 参考模板：`server/config_example.yaml`

项目对部分配置项提供了默认值，见 `server/config/config.go`。因此模板中未写出的增强项，也可以在实际 `config.yaml` 中继续补充。

### 关键配置项

| 配置项 | 说明 |
| --- | --- |
| `app.port` | 后端监听端口 |
| `database.dsn` | MySQL 连接串 |
| `redis.enabled` | 是否启用 Redis 缓存 |
| `security.demoMode` | 是否优先按演示模式运行 |
| `security.source.geoLite2.*` | GeoLite2 本地库配置 |
| `security.source.rdap.*` | RDAP 主端点与备用端点配置 |
| `security.source.localBlacklist.*` | 本地黑名单与 CIDR 名单配置 |
| `security.source.abuseIPDB.*` | 信誉增强源配置，默认可关闭 |
| `security.source.attackSurface.*` | 有限端口探测与 Nmap 增强开关 |
| `security.source.flow.*` | 流量增强开关、模式、窗口、超时配置 |
| `security.alert.*` | 预警通知与邮件字段 |
| `security.weights.*` | 评分权重配置 |

### 流量模式

| 模式 | 说明 |
| --- | --- |
| `disabled` | 关闭流量维能力，不进入默认来源链和评分说明 |
| `sample` | 样本原型模式，便于演示与联调 |
| `offline_pcap` | 离线 `pcap/pcapng` 真实解析 |
| `online_capture` | 在线短时抓包，依赖网卡与抓包环境 |

### 环境检查命令

在 Windows / PowerShell 中可先做以下检查：

```powershell
go version
node -v
npm -v
mysql --version
redis-server --version
nmap --version
```

`nmap --version` 只用于确认 Nmap 增强环境；未安装不影响默认 `limited-port-scan`。Npcap 没有统一的命令行检查方式，建议通过 `/api/v1/configs/security/flow-interfaces` 或前端安全配置页确认后端能否枚举网卡。

## 默认账号与权限

系统会自动确保默认演示账号存在，`demo_seed.sql` 也会导入同名账号。

| 用户名 | 密码 | 角色 | 主要权限 |
| --- | --- | --- | --- |
| `admin` | `Admin123!` | `ADMIN` | 全量访问、用户管理、配置管理、操作审计 |
| `manager` | `Admin123!` | `MANAGER` | 安全任务、配置管理、流量监控 |
| `user` | `Admin123!` | `USER` | 查看总览、任务、历史、预警、实时监控 |

## 关键页面与接口

### 页面入口

- `/login`
- `/security/overview`
- `/security/task`
- `/security/task/:id`
- `/security/history`
- `/security/monitor`
- `/security/alert`
- `/security/alert/:id`
- `/security/config`
- `/system/users`
- `/system/audit-logs`

### 核心 API

#### 系统域

- `POST /api/v1/system/login`
- `POST /api/v1/system/logout`
- `GET /api/v1/system/user/info`
- `GET /api/v1/system/users`
- `POST /api/v1/system/users`
- `PATCH /api/v1/system/users/:id/status`
- `PATCH /api/v1/system/users/:id/password`
- `GET /api/v1/system/audit-logs`

#### 安全域

- `POST /api/v1/tasks`
- `GET /api/v1/tasks`
- `GET /api/v1/tasks/:id`
- `DELETE /api/v1/tasks/:id`
- `GET /api/v1/dashboard/summary`
- `GET /api/v1/dashboard/geo-risk`
- `GET /api/v1/alerts`
- `GET /api/v1/alerts/:id`
- `GET /api/v1/records`
- `GET /api/v1/configs/security`
- `PUT /api/v1/configs/security`
- `GET /api/v1/configs/security/flow-interfaces`
- `PATCH /api/v1/configs/security/flow-toggle`
- `POST /api/v1/flow-monitor/sessions`
- `GET /api/v1/flow-monitor/sessions/:id`
- `POST /api/v1/flow-monitor/sessions/:id/stop`
- `GET /api/v1/flow-monitor/tasks/:id/relation-graph`

## 数据源与流量模式

### 数据源优先级

#### 基础画像层

- `GeoLite2 Country / City / ASN`
- `RDAP`
- 本地黑名单 / CIDR 名单

#### 信誉与攻击面增强层

- `AbuseIPDB`
- Go 原生有限端口探测

#### 流量与原型增强层

- `Nmap`
- `gopacket`
- 应用层协议特征
- 网络设备日志补充

### 当前默认执行口径

- 基础画像优先读取本地 `GeoLite2`
- `GeoLite2` 缺库、缺字段或查询为空时回退到 `RDAP`
- `RDAP` 默认按 `baseURL -> backupBaseURLs` 顺序轮询
- 成功结果可缓存，失败结果不缓存
- 缓存命名空间随 `target_ip + source_name + config_version` 变化自动隔离
- Nmap 只作为可开关增强，不可用时必须回退到 Go 原生有限端口探测
- Npcap + `gopacket/pcap` 只作为在线抓包、实时监控和网卡枚举的运行环境，不是所有任务的默认前置条件

### 当前流量边界

- `offline_pcap`：已真实解析、真实落库、真实页面承接
- `online_capture`：已具备短时真实抓包路线
- 不做常驻守护进程
- 不将流量增强能力作为默认业务主链的硬依赖
- 离线解析依赖可读取的 `pcap/pcapng` 文件，在线抓包依赖 Npcap、网卡名和运行权限

## 文档

### 核心文档

- `docs/功能说明.md`：[项目功能介绍](docs/功能说明.md)
- `docs/架构说明.md`：[架构说明](docs/架构说明.md)
- `docs/api接口约束.md`：[接口约束](docs/api接口约束.md)
- `docs/评分算法整体框架.md`：[评分算法框架](docs/评分算法整体框架.md)

- `docs/系统设计.md`：[系统设计](docs/系统设计.md)
