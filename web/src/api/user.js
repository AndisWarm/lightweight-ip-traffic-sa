import request from './request'

export const login = (data) => request.post('/system/login', data)
export const logout = () => request.post('/system/logout')
export const getUserInfo = () => request.get('/system/user/info')
export const getUserList = () => request.get('/system/users')
export const createUser = (data) => request.post('/system/users', data)
export const updateUserStatus = (id, data) => request.patch(`/system/users/${id}/status`, data)
export const resetUserPassword = (id, data) => request.patch(`/system/users/${id}/password`, data)
