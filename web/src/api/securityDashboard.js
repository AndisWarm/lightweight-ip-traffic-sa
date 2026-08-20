// 态势总览数据接口：汇总指标与地理风险分布（热力图数据源）。
import request from './request'

export const getSecuritySummary = () => request.get('/dashboard/summary')
export const getSecurityGeoRisk = () => request.get('/dashboard/geo-risk')
