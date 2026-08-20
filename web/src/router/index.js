import { createRouter, createWebHistory } from 'vue-router'
import { ElMessage } from 'element-plus'

import securityRoutes from './modules/security'
import pinia from '../pinia'
import { useUserStore } from '../pinia/modules/user'
import { getStoredToken } from '../utils/authState'

const routes = [
  {
    path: '/',
    redirect: '/security/overview',
  },
  {
    path: '/login',
    name: 'Login',
    component: () => import('../view/login/index.vue'),
    meta: {
      public: true,
      title: '用户登录',
    },
  },
  ...securityRoutes,
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

const loginExpiredMessages = ['未登录或登录状态已失效', '登录状态已失效']

router.beforeEach(async (to, from, next) => {
  const userStore = useUserStore(pinia)
  const requiresAuth = to.matched.some((record) => record.meta.requiresAuth)

  if (!requiresAuth) {
    if (to.path === '/login' && userStore.isLoggedIn) {
      try {
        await userStore.ensureUserLoaded()
        next('/security/overview')
      } catch (error) {
        userStore.handleAuthExpired(error?.message)
        if (loginExpiredMessages.includes(error?.message)) {
          ElMessage.warning('登录状态已失效，请重新登录')
        } else if (error?.message) {
          ElMessage.error(error.message)
        }
        next()
      }
      return
    }
    next()
    return
  }

  if (!userStore.isLoggedIn) {
    if (!getStoredToken()) {
      ElMessage.warning('请先登录后再访问该页面')
    }
    next('/login')
    return
  }

  try {
    await userStore.ensureUserLoaded()
  } catch (error) {
    userStore.handleAuthExpired(error?.message)
    if (error?.message && !loginExpiredMessages.includes(error.message)) {
      ElMessage.error(error.message)
    }
    next('/login')
    return
  }

  const routeRoles = to.meta.roles || []
  if (routeRoles.length && !routeRoles.includes(userStore.roleCode)) {
    ElMessage.warning('当前账号无权访问该页面')
    next('/security/overview')
    return
  }

  next()
})

export default router
