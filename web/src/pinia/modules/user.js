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

export const ROLE_ADMIN = 'ADMIN'
export const ROLE_MANAGER = 'MANAGER'
export const ROLE_USER = 'USER'

export const useUserStore = defineStore('user', {
  state: () => ({
    token: getStoredToken(),
    userInfo: null,
    loaded: false,
  }),
  getters: {
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
      this.token = token
      setStoredToken(token)
    },
    async loginByPassword(payload) {
      const resp = await login(payload)
      const data = resp.data.data
      this.setToken(data.token)
      this.userInfo = data.user
      this.loaded = true
      return data
    },
    async fetchUserInfo() {
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
