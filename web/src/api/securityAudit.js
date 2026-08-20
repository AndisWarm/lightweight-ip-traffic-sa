// 系统审计日志接口：管理员侧查看操作审计列表。
import request from './request'

export const getAuditLogs = (params) => request.get('/system/audit-logs', { params })
