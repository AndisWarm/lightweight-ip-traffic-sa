// 安全配置接口：读取/更新评分权重、风险阈值与特征源；流量开关用 PATCH 做局部更新，避免覆盖整个配置对象。
import request from './request'

export const getSecurityConfig = () => request.get('/configs/security')
export const getFlowInterfaces = () => request.get('/configs/security/flow-interfaces')
export const updateSecurityConfig = (data) => request.put('/configs/security', data)
export const updateFlowToggle = (enabled) => request.patch('/configs/security/flow-toggle', { enabled })
