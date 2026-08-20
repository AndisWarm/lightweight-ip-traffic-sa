// 统一历史记录接口：任务与预警事件共用的时间线查询。
import request from './request'

export const getSecurityRecordList = (params) => request.get('/records', { params })
