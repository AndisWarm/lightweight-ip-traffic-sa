# 接口约定

## 1. 总体约定

### 1.1 路径前缀

- 后端统一以前缀 `/api/v1` 提供接口
- 前端统一通过 `web/src/api/request.js` 中的 Axios 实例访问

### 1.2 认证方式

- 登录成功后，请求头使用 `Authorization: Bearer <token>`
- 除 `POST /api/v1/system/login` 外，其余当前接口都要求 JWT

### 1.3 统一响应结构

当前统一响应结构位于：

- `server/model/security/response/base.go`

响应格式：

```json
{
  "code": 0,
  "message": "success",
  "data": {}
}
```

说明：

- `code = 0` 表示成功
- `code = 1` 表示失败
- 当前项目主要依赖 HTTP 状态码与 `message` 共同表达错误

### 1.4 前端异常处理

`web/src/api/request.js` 当前约定如下：

1. 401
   - 清理本地 token
   - 非登录页场景跳回 `/login`
   - 提示“登录已失效，请重新登录”
2. 403
   - 优先展示后端返回消息
   - 无明确消息时展示“当前账号无权执行此操作”
3. 500+
   - 无明确消息时展示“系统开小差了，请稍后重试”

## 2. 系统域接口

### 2.1 登录

- 路径：`POST /api/v1/system/login`
- 是否鉴权：否
- 请求体：

```json
{
  "username": "admin",
  "password": "Admin123!"
}
```

- 返回重点字段：

```json
{
  "token": "jwt-token",
  "user": {
    "id": 1,
    "username": "admin",
    "displayName": "Admin",
    "roleCode": "ADMIN",
    "roleName": "管理员",
    "enable": true,
    "createdAt": "2026-04-06T00:00:00Z"
  }
}
```

### 2.2 登出

- 路径：`POST /api/v1/system/logout`
- 是否鉴权：是

### 2.3 当前用户

- 路径：`GET /api/v1/system/user/info`
- 是否鉴权：是
- 返回重点字段：
  - `user.id`
  - `user.username`
  - `user.displayName`
  - `user.roleCode`
  - `user.roleName`
  - `user.enable`

### 2.4 用户列表

- 路径：`GET /api/v1/system/users`
- 是否鉴权：是
- 角色要求：`ADMIN`
- 返回重点字段：
  - `list[].id`
  - `list[].username`
  - `list[].displayName`
  - `list[].roleCode`
  - `list[].roleName`
  - `list[].enable`
  - `list[].createdAt`

### 2.5 新增用户

- 路径：`POST /api/v1/system/users`
- 是否鉴权：是
- 角色要求：`ADMIN`
- 请求体重点字段：
  - `username`
  - `displayName`
  - `password`
  - `roleCode`
  - `enable`

### 2.6 用户状态更新

- 路径：`PATCH /api/v1/system/users/:id/status`
- 是否鉴权：是
- 角色要求：`ADMIN`
- 请求体重点字段：
  - `enable`

### 2.7 密码重置

- 路径：`PATCH /api/v1/system/users/:id/password`
- 是否鉴权：是
- 角色要求：`ADMIN`
- 请求体重点字段：
  - `password`

## 3. 安全域接口

### 3.1 任务创建

- 路径：`POST /api/v1/tasks`
- 是否鉴权：是
- 角色要求：`ADMIN`、`MANAGER`
- 请求体：

```json
{
  "targetIp": "8.8.8.8",
  "requestedBy": "admin"
}
```

- 返回重点字段：
  - `taskId`
  - `taskNo`
  - `targetIp`
  - `taskStatus`
  - `scoreValue`
  - `riskLevel`
  - `alertCreated`

### 3.2 任务列表

- 路径：`GET /api/v1/tasks`
- 是否鉴权：是
- 查询参数：

| 参数 | 说明 | 可选值 |
|---|---|---|
| `page` | 页码 | 正整数 |
| `pageSize` | 每页条数 | 正整数 |
| `targetIp` | 目标 IP 筛选 | 字符串 |
| `taskStatus` | 任务状态 | `PENDING` `RUNNING` `SUCCESS` `FAILED` |
| `riskLevel` | 风险等级 | `LOW` `MEDIUM` `HIGH` `CRITICAL` |
| `sortBy` | 排序字段 | `createdAt` `scoreValue` `riskLevel` |
| `sortOrder` | 排序方向 | `asc` `desc` |

- 返回重点字段：
  - `page`
  - `pageSize`
  - `total`
  - `sortBy`
  - `sortOrder`
  - `items[].taskId`
  - `items[].taskNo`
  - `items[].targetIp`
  - `items[].taskStatus`
  - `items[].scoreValue`
  - `items[].riskLevel`
  - `items[].createdAt`

### 3.3 任务详情

- 路径：`GET /api/v1/tasks/:id`
- 是否鉴权：是
- 返回重点字段：
  - 基础字段：
    - `taskId`
    - `taskNo`
    - `targetIp`
    - `taskStatus`
    - `scoreValue`
    - `riskLevel`
    - `alertCreated`
    - `createdBy`
    - `startedAt`
    - `finishedAt`
    - `createdAt`
    - `errorMessage`
  - 基础画像：
    - `baseInfo.country`
    - `baseInfo.region`
    - `baseInfo.city`
    - `baseInfo.isp`
    - `baseInfo.whoisOrg`
    - `baseInfo.whoisContact`
  - 特征结果：
    - `features.reputationScore`
    - `features.openPortCount`
    - `features.highRiskPortCount`
    - `features.geoRiskFlag`
    - `features.featureDigest`
    - `features.normalizedFeatures`
  - 评分结果：
    - `score.scoreValue`
    - `score.riskLevel`
    - `score.scoreReason`
    - `score.ruleAdjustment`
    - `score.isAlertTriggered`
  - 预警摘要：
    - `alert.alertId`
    - `alert.alertLevel`
    - `alert.alertTitle`
    - `alert.alertContent`
    - `alert.channel`
    - `alert.sendStatus`
    - `alert.sendTime`
    - `alert.createdAt`

### 3.4 总览统计

- 路径：`GET /api/v1/dashboard/summary`
- 是否鉴权：是
- 返回字段：
  - `totalTaskCount`
  - `highRiskCount`
  - `criticalRiskCount`
  - `alertCount`
  - `todayDetections`

说明：

- 当前总览统计结果在 Redis 可用时会做 `30s` 短缓存

### 3.5 预警列表

- 路径：`GET /api/v1/alerts`
- 是否鉴权：是
- 查询参数：

| 参数 | 说明 |
|---|---|
| `page` | 页码 |
| `pageSize` | 每页条数 |
| `targetIp` | 目标 IP |
| `alertLevel` | 预警等级 |
| `sendStatus` | 发送状态 |
| `channel` | 通知渠道 |

- 返回重点字段：
  - `page`
  - `pageSize`
  - `total`
  - `items[].alertId`
  - `items[].taskNo`
  - `items[].targetIp`
  - `items[].alertLevel`
  - `items[].channel`
  - `items[].sendStatus`
  - `items[].createdAt`

### 3.6 预警详情

## 4. 2026-04-14 新增接口补充

### 4.1 实时流量监控会话

- `POST /api/v1/flow-monitor/sessions`
- 角色要求：`ADMIN`、`MANAGER`
- 请求体字段：
  - `targetIp`
  - `interfaceName`
  - `windowSeconds`
  - `timeoutSeconds`
  - `bindTaskId`
- 返回重点字段：
  - `sessionId`
  - `status`
  - `summary`
  - `packetCount`
  - `conversationCount`
  - `behaviorRiskScore`
  - `protocolDistribution`
  - `dnsTopQuestions`
  - `httpHostHints`
  - `tlsHandshakeHints`
  - `directionalityIndicators`
  - `payloadEntropyIndicators`

- `GET /api/v1/flow-monitor/sessions/:id`
- 返回单次短时抓包会话的当前结果快照。

- `POST /api/v1/flow-monitor/sessions/:id/stop`
- 角色要求：`ADMIN`、`MANAGER`
- 用于停止当前短时会话并返回停止后的会话状态。

### 4.2 风险 IP 热力图

- `GET /api/v1/dashboard/geo-risk`
- 返回最近 7 天基于任务、预警和基础画像聚合的风险 IP 地理点位。
- 返回重点字段：
  - `items[].targetIp`
  - `items[].country`
  - `items[].region`
  - `items[].city`
  - `items[].riskLevel`
  - `items[].taskCount`
  - `items[].alertCount`
  - `items[].latitude`
  - `items[].longitude`
  - `items[].hasCoordinate`

### 4.3 任务级 IP-流量关联图谱

- `GET /api/v1/flow-monitor/tasks/:id/relation-graph`
- 返回单任务范围内的 IP、对端、协议、端口、域名 / SNI 关联关系。
- 返回重点字段：
  - `taskId`
  - `nodes[].id`
  - `nodes[].label`
  - `nodes[].category`
  - `nodes[].value`
  - `nodes[].meta`
  - `edges[].source`
  - `edges[].target`
  - `edges[].label`
  - `edges[].value`

### 4.4 系统审计日志

- `GET /api/v1/system/audit-logs`
- 角色要求：`ADMIN`
- 查询参数：
  - `page`
  - `pageSize`
  - `category`
  - `action`
  - `actor`
  - `status`
- 返回重点字段：
  - `page`
  - `pageSize`
  - `total`
  - `categories`
  - `items[].category`
  - `items[].action`
  - `items[].actor`
  - `items[].targetType`
  - `items[].targetId`
  - `items[].targetLabel`
  - `items[].status`
  - `items[].summary`
  - `items[].createdAt`

### 4.5 评分结果扩展字段

- 任务详情 `score` 和预警详情 `score` 已扩展以下字段：
  - `baseScore`
  - `reputationScore`
  - `attackSurfaceScore`
  - `behaviorScore`
  - `ruleAdjustmentValue`
  - `algorithmVersion`
  - `weightProfile`

### 4.6 配置接口扩展字段

- `GET /api/v1/configs/security`
- `PUT /api/v1/configs/security`

新增 SMTP / 邮件相关字段：
- `mailEnabled`
- `mailSender`
- `mailRecipient`
- `smtpHost`
- `smtpPort`
- `smtpUsername`
- `smtpUseTLS`

- 路径：`GET /api/v1/alerts/:id`
- 是否鉴权：是
- 返回重点字段：
  - 预警字段：
    - `alertId`
    - `alertLevel`
    - `alertTitle`
    - `alertContent`
    - `channel`
    - `sendStatus`
    - `sendTime`
    - `createdAt`
  - 关联任务：
    - `task.taskId`
    - `task.taskNo`
    - `task.targetIp`
    - `task.taskStatus`
  - 关联评分：
    - `score.scoreValue`
    - `score.riskLevel`
    - `score.scoreReason`

### 3.7 历史记录

- 路径：`GET /api/v1/records`
- 是否鉴权：是
- 查询参数：

| 参数 | 说明 | 可选值 |
|---|---|---|
| `page` | 页码 | 正整数 |
| `pageSize` | 每页条数 | 正整数 |
| `eventType` | 事件类型 | `ALL` `TASK` `ALERT` |
| `keyword` | 关键字搜索 | 字符串 |

- 返回重点字段：
  - `page`
  - `pageSize`
  - `total`
  - `items[].id`
  - `items[].eventType`
  - `items[].title`
  - `items[].description`
  - `items[].targetIp`
  - `items[].taskNo`
  - `items[].level`
  - `items[].status`
  - `items[].time`
  - `items[].detailRoute`

说明：

- 当前历史记录由任务和预警两类记录合并生成，不是单表直出

### 3.8 安全配置读取

- 路径：`GET /api/v1/configs/security`
- 是否鉴权：是
- 返回重点字段：
  - `whoisEndpoint`
  - `reputationEndpoint`
  - `notifyChannel`
  - `highRiskThreshold`
  - `criticalRiskThreshold`
  - `weights.whoisWeight`
  - `weights.reputationWeight`
  - `weights.attackSurfaceWeight`
  - `weights.behaviorWeight`

说明：

- 当前配置查询在 Redis 可用时会做 `5m` 缓存

### 3.9 安全配置更新

- 路径：`PUT /api/v1/configs/security`
- 是否鉴权：是
- 角色要求：`ADMIN`、`MANAGER`
- 请求体：

```json
{
  "whoisEndpoint": "local-demo",
  "reputationEndpoint": "local-demo",
  "notifyChannel": "SYSTEM",
  "highRiskThreshold": 75,
  "criticalRiskThreshold": 90,
  "weights": {
    "whoisWeight": 0.2,
    "reputationWeight": 0.35,
    "attackSurfaceWeight": 0.3,
    "behaviorWeight": 0.15
  }
}
```

- 返回：最新安全配置对象

## 4. 前端 API 对应关系

| 前端文件 | 对应接口 |
|---|---|
| `web/src/api/user.js` | 系统登录、用户与认证相关接口 |
| `web/src/api/securityTask.js` | 任务创建、列表、详情 |
| `web/src/api/securityDashboard.js` | 总览统计 |
| `web/src/api/securityAlert.js` | 预警列表、预警详情 |
| `web/src/api/securityRecord.js` | 历史记录 |
| `web/src/api/securityConfig.js` | 安全配置读取与更新 |

截至 `2026-04-06`，上述前端 API 路径已与当前后端路由实现完成静态核对。

## 5. 实现注意事项

1. 不要跳过统一响应封装，避免接口返回风格漂移。
2. 改接口时必须同步检查：
   - 后端路由
   - API 层
   - request/response 模型
   - 对应前端 `web/src/api/*.js`
   - 对应页面
3. 需要权限的接口要同时检查后端角色限制与前端页面可见性控制。
4. 文档中的字段应以当前 `request/response` 模型为准，不要按前端临时拼装字段反推接口契约。
