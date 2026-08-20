// Layout 是带侧边栏/顶栏的外壳组件，安全域与系统域页面都嵌在其中渲染，避免每页重复写布局。
import Layout from '../../view/layout/index.vue'

// 安全域 + 系统域路由集中定义：父路由统一挂 Layout 与 requiresAuth，子路由只声明业务页面与可访问角色。
export default [
  {
    path: '/security',
    component: Layout,
    meta: {
      // 父级 requiresAuth 会被子路由通过 to.matched 继承，无需每个子路由重复声明。
      requiresAuth: true,
    },
    children: [
      {
        path: 'overview',
        name: 'SecurityOverview',
        component: () => import('../../view/security/overview/index.vue'),
        meta: {
          title: '态势总览',
          // roles 是可访问角色白名单：三个角色都能看；越靠后的页面（配置/用户面板）角色收得越窄。
          roles: ['ADMIN', 'MANAGER', 'USER'],
        },
      },
      {
        path: 'task',
        name: 'SecurityTask',
        component: () => import('../../view/security/task/index.vue'),
        meta: {
          title: '检测任务',
          roles: ['ADMIN', 'MANAGER', 'USER'],
        },
      },
      {
        path: 'task/:id',
        name: 'SecurityTaskDetail',
        component: () => import('../../view/security/task/detail/index.vue'),
        meta: {
          title: '任务详情',
          roles: ['ADMIN', 'MANAGER', 'USER'],
        },
      },
      {
        path: 'history',
        name: 'SecurityHistory',
        component: () => import('../../view/security/history/index.vue'),
        meta: {
          title: '检测历史',
          roles: ['ADMIN', 'MANAGER', 'USER'],
        },
      },
      {
        path: 'monitor',
        name: 'SecurityFlowMonitor',
        component: () => import('../../view/security/monitor/index.vue'),
        meta: {
          title: '实时流量监控',
          roles: ['ADMIN', 'MANAGER', 'USER'],
        },
      },
      {
        path: 'user-monitor-panel',
        name: 'SecurityUserMonitorPanel',
        component: () => import('../../view/security/monitor-panel/index.vue'),
        meta: {
          title: '用户实时流量面板',
          roles: ['ADMIN', 'MANAGER'],
        },
      },
      {
        path: 'alert',
        name: 'SecurityAlert',
        component: () => import('../../view/security/alert/index.vue'),
        meta: {
          title: '预警中心',
          roles: ['ADMIN', 'MANAGER', 'USER'],
        },
      },
      {
        path: 'alert/:id',
        name: 'SecurityAlertDetail',
        component: () => import('../../view/security/alert/detail/index.vue'),
        meta: {
          title: '预警详情',
          roles: ['ADMIN', 'MANAGER', 'USER'],
        },
      },
      {
        path: 'config',
        name: 'SecurityConfig',
        component: () => import('../../view/security/config/index.vue'),
        meta: {
          title: '系统配置',
          roles: ['ADMIN', 'MANAGER'],
        },
      },
    ],
  },
  {
    // 系统域：仅 ADMIN 可访问（用户管理、操作审计），父级直接声明 roles 整段拦截，无需逐个子路由判断。
    path: '/system',
    component: Layout,
    meta: {
      requiresAuth: true,
      roles: ['ADMIN'],
    },
    children: [
      {
        path: 'users',
        name: 'SystemUserManage',
        component: () => import('../../view/system/user/index.vue'),
        meta: {
          title: '用户管理',
          roles: ['ADMIN'],
        },
      },
      {
        path: 'audit-logs',
        name: 'SystemAuditLogs',
        component: () => import('../../view/system/audit/index.vue'),
        meta: {
          title: '操作审计',
          roles: ['ADMIN'],
        },
      },
    ],
  },
]
