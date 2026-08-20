// 检测任务接口：创建 / 列表 / 详情 / 删除 / 关系图。创建任务单独放宽超时，见下方说明。
import request from './request'

export const createSecurityTask = (data) => request.post('/tasks', data, {
  // 在线抓包与多源检测链路可能超过默认 10 秒，请求创建任务时放宽等待时间。
  timeout: 60000,
})
export const getSecurityTaskList = (params) => request.get('/tasks', { params })
export const getSecurityTaskDetail = (id) => request.get(`/tasks/${id}`)
export const deleteSecurityTask = (id) => request.delete(`/tasks/${id}`)
export const getSecurityTaskRelationGraph = (id) => request.get(`/flow-monitor/tasks/${id}/relation-graph`)
