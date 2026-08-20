import { createRouter, createWebHistory } from 'vue-router'
import { ElMessage } from 'element-plus'

import securityRoutes from './modules/security'
import pinia from '../pinia'
import { useUserStore } from '../pinia/modules/user'
import { getStoredToken } from '../utils/authState'

// 顶层路由表：根路径重定向到态势总览；登录页声明为公开页；其余安全域/系统域路由从 modules/security 平铺合并进来。
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

// 使用 HTML5 History 模式：URL 无 # 号更接近普通站点；需后端/网关把未知路径回退到 index.html，否则刷新会 404。
const router = createRouter({
  history: createWebHistory(),
  routes,
})

// 后端可能在"未登录/登录过期"时返回不同文案，这里收集成白名单：
// 只有命中这些文案才走"会话失效"的轻提示，其余错误按原样展示，避免误把普通错误当登录失效。
const loginExpiredMessages = ['未登录或登录状态已失效', '登录状态已失效']

// 全局前置守卫：每次路由跳转前依次校验——页面是否需要登录、是否已有 token、用户信息是否已加载、角色是否匹配。
router.beforeEach(async (to, from, next) => {
  const userStore = useUserStore(pinia)
  // to.matched 是匹配到的整条路由链（父 + 子），用 some 判断可让子路由继承父级 requiresAuth，避免逐条重复声明。
  const requiresAuth = to.matched.some((record) => record.meta.requiresAuth)

  // 第一步：公开页面直接放行；但对"已登录还访问登录页"做反向跳转，避免重复登录。
  if (!requiresAuth) {
    if (to.path === '/login' && userStore.isLoggedIn) {
      // 已登录用户再进登录页：先确保用户信息可用，成功则送回总览页；若 token 已失效则留在登录页并提示。
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

  // 第二步：需要登录但没有 token，直接引导到登录页；无 token 时给一次友好提示。
  if (!userStore.isLoggedIn) {
    if (!getStoredToken()) {
      ElMessage.warning('请先登录后再访问该页面')
    }
    next('/login')
    return
  }

  // 第三步：有 token 但用户信息尚未拉取（首次进入或刷新后），先补拉一次；失败说明 token 失效，清态并回登录页。
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

  // 角色权限校验：meta.roles 声明"可访问角色白名单"；为空表示不限制，否则当前角色必须出现在列表里。
  const routeRoles = to.meta.roles || []
  if (routeRoles.length && !routeRoles.includes(userStore.roleCode)) {
    // 角色不匹配：提示后统一送回态势总览（所有角色都可访问的安全落地页），而不是硬跳 403 死页。
    ElMessage.warning('当前账号无权访问该页面')
    next('/security/overview')
    return
  }

  next()
})

export default router
