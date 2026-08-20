import request from './request'

export const getSecurityAlertList = (params) => request.get('/alerts', { params })
export const getSecurityAlertDetail = (id) => request.get(`/alerts/${id}`)
