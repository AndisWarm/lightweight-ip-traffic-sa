import { defineStore } from 'pinia'

import {
  createUser,
  getUserInfo,
  getUserList,
  login,
  logout,
  resetUserPassword,
  updateUserStatus,
} from '../../api/user'
import { clearStoredToken, getStoredToken, setStoredToken } from '../../utils/authState'

// 角色枚举：与后端约定一致，前端据此做按钮显隐与路由/操作级权限判断。
export const ROLE_ADMIN = 'ADMIN'
export const ROLE_MANAGER = 'MANAGER'
export const ROLE_USER = 'USER'

export const useUserStore = defineStore('user', {
  // state 初始化：token 直接从 localStorage 读回，实现刷新后登录态不丢失；loaded 标记用户信息是否已拉取。
  state: () => ({
    token: getStoredToken(),
    userInfo: null,
    loaded: false,
  }),
  // getters 集中派生"是否登录/角色/显示名/权限开关"，页面与守卫复用这些语义，避免散落各处判断。
  getters: {
    // 只要 token 非空即视为已登录；其是否仍然有效由后续请求返回 401 兜底。
    isLoggedIn: (state) => Boolean(state.token),
    roleCode: (state) => state.userInfo?.roleCode || '',
    displayName: (state) => state.userInfo?.displayName || '',
    username: (state) => state.userInfo?.username || '',
    isAdmin: (state) => state.userInfo?.roleCode === ROLE_ADMIN,
    isManager: (state) => state.userInfo?.roleCode === ROLE_MANAGER,
    isUser: (state) => state.userInfo?.roleCode === ROLE_USER,
    canManageUsers() {
      return this.roleCode === ROLE_ADMIN
    },
    canCreateTask() {
      return this.roleCode === ROLE_ADMIN || this.roleCode === ROLE_MANAGER
    },
    canEditConfig() {
      return this.roleCode === ROLE_ADMIN || this.roleCode === ROLE_MANAGER
    },
    canViewConfig() {
      return this.roleCode === ROLE_ADMIN || this.roleCode === ROLE_MANAGER
    },
  },
  actions: {
    setToken(token) {
      // 更新 token 的同时写回 localStorage，保持内存态与持久化一致，防止刷新后丢失登录态。
      this.token = token
      setStoredToken(token)
    },
    async loginByPassword(payload) {
      const resp = await login(payload)
      const data = resp.data.data
      // 登录成功：先落 token，再存用户信息并标记已加载，后续守卫/页面可直接读取。
      this.setToken(data.token)
      this.userInfo = data.user
      this.loaded = true
      return data
    },
    async fetchUserInfo() {
      // 无 token 时不发请求，直接置空并视为已加载，避免无效的 401 请求白跑一次。
      if (!this.token) {
        this.userInfo = null
        this.loaded = true
        return null
      }
      const resp = await getUserInfo()
      this.userInfo = resp.data.data.user
      this.loaded = true
      return this.userInfo
    },
    async logoutAction() {
      // 登出：先尝试通知后端（可能失败），但无论成败都要清本地 token 与用户态，保证前端一定登出。
      try {
        if (this.token) {
          await logout()
        }
      } finally {
        this.token = ''
        clearStoredToken()
        this.userInfo = null
        this.loaded = true
      }
    },
    async ensureUserLoaded() {
      // 按需加载：无 token 直接返回；已加载且有用户信息则命中缓存，否则才真正请求，避免每次跳转重复拉取。
      if (!this.token) {
        this.loaded = true
        return null
      }
      if (this.loaded && this.userInfo) {
        return this.userInfo
      }
      return this.fetchUserInfo()
    },
    handleAuthExpired(message) {
      // 登录失效统一清理：清内存 token、删 localStorage、重置用户态；返回 message 便于调用方继续提示。
      this.token = ''
      clearStoredToken()
      this.userInfo = null
      this.loaded = true
      return message
    },
    async fetchUserList() {
      const resp = await getUserList()
      return resp.data.data.list || []
    },
    async createUserAction(payload) {
      return createUser(payload)
    },
    async updateUserStatusAction(id, enable) {
      return updateUserStatus(id, { enable })
    },
    async resetPasswordAction(id, password) {
      return resetUserPassword(id, { password })
    },
  },
})
