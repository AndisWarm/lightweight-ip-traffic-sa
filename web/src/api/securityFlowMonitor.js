// 实时流量监控接口：一个抓包会话从开启到停止的完整生命周期，以及观测面板与任务关系图数据。
import request from './request'

export const startFlowMonitorSession = (data) => request.post('/flow-monitor/sessions', data)

export const getCurrentFlowMonitorSession = () => request.get('/flow-monitor/sessions/current')
export const getFlowMonitorSession = (id) => request.get(`/flow-monitor/sessions/${id}`)
export const stopFlowMonitorSession = (id) => request.post(`/flow-monitor/sessions/${id}/stop`)
export const getFlowMonitorObserverPanel = (params) => request.get('/flow-monitor/observer-panel', { params })
export const getTaskRelationGraph = (taskId) => request.get(`/flow-monitor/tasks/${taskId}/relation-graph`)
