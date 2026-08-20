import request from './request'

export const getSecurityConfig = () => request.get('/configs/security')
export const getFlowInterfaces = () => request.get('/configs/security/flow-interfaces')
export const updateSecurityConfig = (data) => request.put('/configs/security', data)
export const updateFlowToggle = (enabled) => request.patch('/configs/security/flow-toggle', { enabled })
