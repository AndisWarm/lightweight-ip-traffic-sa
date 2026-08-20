// 系统用户域接口：登录/登出/当前用户信息，以及管理员对用户的列表、创建、状态与密码维护。
import request from './request'

export const login = (data) => request.post('/system/login', data)
export const logout = () => request.post('/system/logout')
export const getUserInfo = () => request.get('/system/user/info')
export const getUserList = () => request.get('/system/users')
export const createUser = (data) => request.post('/system/users', data)
export const updateUserStatus = (id, data) => request.patch(`/system/users/${id}/status`, data)
export const resetUserPassword = (id, data) => request.patch(`/system/users/${id}/password`, data)
