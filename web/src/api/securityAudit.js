import request from './request'

export const getAuditLogs = (params) => request.get('/system/audit-logs', { params })
