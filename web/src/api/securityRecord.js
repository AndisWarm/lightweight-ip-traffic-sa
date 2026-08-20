import request from './request'

export const getSecurityRecordList = (params) => request.get('/records', { params })
