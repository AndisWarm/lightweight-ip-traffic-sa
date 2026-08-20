// 预警中心接口：列表查询与详情查询，路径挂在统一 baseURL(/api/v1) 之下。
import request from './request'

export const getSecurityAlertList = (params) => request.get('/alerts', { params })
export const getSecurityAlertDetail = (id) => request.get(`/alerts/${id}`)
