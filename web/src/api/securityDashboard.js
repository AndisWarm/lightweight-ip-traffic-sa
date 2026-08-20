import request from './request'

export const getSecuritySummary = () => request.get('/dashboard/summary')
export const getSecurityGeoRisk = () => request.get('/dashboard/geo-risk')
