// 后端枚举码 → 前端展示文案的统一映射：页面只依赖这些函数取值，后端改枚举值只需改这一处。
export const riskLevelTextMap = {
  LOW: '低风险',
  MEDIUM: '中风险',
  HIGH: '高风险',
  CRITICAL: '严重风险',
}

export const taskStatusTextMap = {
  PENDING: '待执行',
  RUNNING: '执行中',
  SUCCESS: '已完成',
  FAILED: '执行失败',
}

export const sendStatusTextMap = {
  PENDING: '待发送',
  SUCCESS: '发送成功',
  FAILED: '发送失败',
}

// 各枚举 → Element Plus 标签色的映射：风险等级/任务状态/发送状态/预警等级分别对应颜色，保证全局配色一致。
export const riskLevelTagMap = {
  LOW: 'success',
  MEDIUM: 'warning',
  HIGH: 'danger',
  CRITICAL: 'danger',
}

export const taskStatusTagMap = {
  PENDING: 'warning',
  RUNNING: 'primary',
  SUCCESS: 'success',
  FAILED: 'danger',
}

export const sendStatusTagMap = {
  PENDING: 'warning',
  SUCCESS: 'success',
  FAILED: 'danger',
}

export const alertLevelTagMap = {
  HIGH: 'warning',
  CRITICAL: 'danger',
}

// 取值函数统一兜底：未命中枚举时原样返回（或给"未知"/"info"），避免映射缺失导致页面空白或报错。
export const getRiskLevelText = (value) => riskLevelTextMap[value] || value || '未知'
export const getTaskStatusText = (value) => taskStatusTextMap[value] || value || '未知'
export const getSendStatusText = (value) => sendStatusTextMap[value] || value || '未知'
export const getRiskLevelTag = (value) => riskLevelTagMap[value] || 'info'
export const getTaskStatusTag = (value) => taskStatusTagMap[value] || 'info'
export const getSendStatusTag = (value) => sendStatusTagMap[value] || 'info'
export const getAlertLevelTag = (value) => alertLevelTagMap[value] || 'info'
