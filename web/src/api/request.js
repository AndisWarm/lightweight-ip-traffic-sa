import axios from 'axios'

import { getStoredToken, notifyAuthExpired } from '../utils/authState'

const service = axios.create({
  baseURL: '/api/v1',
  timeout: 10000,
})

service.interceptors.request.use((config) => {
  const token = getStoredToken()
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

service.interceptors.response.use(
  (response) => response,
  (error) => {
    const status = error?.response?.status
    const responseMessage = error?.response?.data?.message
    let message = responseMessage || error.message || '请求失败'

    if (status === 401) {
      notifyAuthExpired(responseMessage || '登录已失效，请重新登录')
    }

    if (status === 403) {
      message = responseMessage && responseMessage !== '无权访问当前资源'
        ? responseMessage
        : '当前账号无权执行此操作'
    }

    if (status >= 500 && !responseMessage) {
      message = '系统开小差了，请稍后重试'
    }

    return Promise.reject(new Error(message))
  }
)

export default service
