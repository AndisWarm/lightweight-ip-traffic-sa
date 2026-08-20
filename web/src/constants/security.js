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

export const getRiskLevelText = (value) => riskLevelTextMap[value] || value || '未知'
export const getTaskStatusText = (value) => taskStatusTextMap[value] || value || '未知'
export const getSendStatusText = (value) => sendStatusTextMap[value] || value || '未知'
export const getRiskLevelTag = (value) => riskLevelTagMap[value] || 'info'
export const getTaskStatusTag = (value) => taskStatusTagMap[value] || 'info'
export const getSendStatusTag = (value) => sendStatusTagMap[value] || 'info'
export const getAlertLevelTag = (value) => alertLevelTagMap[value] || 'info'
