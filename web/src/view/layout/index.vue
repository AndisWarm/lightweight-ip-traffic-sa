<template>
  <div class="app-shell">
    <aside class="sidebar">
      <div class="brand">
        <h1>轻量化态势感知</h1>
        <p>IP 与流量多特征融合安全分析平台</p>
      </div>

      <nav class="nav">
        <RouterLink
          v-for="item in visibleMenuItems"
          :key="item.path"
          :to="item.path"
          class="nav-item"
        >
          <span>{{ item.title }}</span>
        </RouterLink>
      </nav>
    </aside>

    <main class="main-content">
      <header class="topbar">
        <div>
          <strong>轻量化 IP 态势感知系统</strong>
          <p>面向安全项目，提供检测、流量承接、预警和审计能力。</p>
        </div>

        <div class="user-box">
          <div class="user-meta">
            <span class="user-name">{{ userStore.displayName || userStore.username }}</span>
            <span class="user-role">{{ roleName }}</span>
          </div>
          <el-button plain @click="handleLogout">退出登录</el-button>
        </div>
      </header>

      <section class="page-container">
        <RouterView />
      </section>
    </main>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { ElMessage } from 'element-plus'
import { useRouter } from 'vue-router'

import { useUserStore } from '../../pinia/modules/user'

const router = useRouter()
const userStore = useUserStore()

const menuItems = [
  { path: '/security/overview', title: '态势总览', roles: ['ADMIN', 'MANAGER', 'USER'] },
  { path: '/security/task', title: '检测任务', roles: ['ADMIN', 'MANAGER', 'USER'] },
  { path: '/security/history', title: '检测历史', roles: ['ADMIN', 'MANAGER', 'USER'] },
  { path: '/security/monitor', title: '实时流量监控', roles: ['ADMIN', 'MANAGER', 'USER'] },
  { path: '/security/user-monitor-panel', title: '用户流量面板', roles: ['ADMIN', 'MANAGER'] },
  { path: '/security/alert', title: '预警中心', roles: ['ADMIN', 'MANAGER', 'USER'] },
  { path: '/system/users', title: '用户管理', roles: ['ADMIN'] },
  { path: '/system/audit-logs', title: '操作审计', roles: ['ADMIN'] },
  { path: '/security/config', title: '系统配置', roles: ['ADMIN', 'MANAGER'] },
]

const visibleMenuItems = computed(() =>
  menuItems.filter((item) => item.roles.includes(userStore.roleCode))
)

const roleName = computed(() => userStore.userInfo?.roleName || '')

const handleLogout = async () => {
  await userStore.logoutAction()
  ElMessage.success('已退出登录')
  router.replace('/login')
}
</script>

<style scoped>
.app-shell {
  min-height: 100vh;
  display: grid;
  grid-template-columns: 240px 1fr;
  align-items: start;
}

.sidebar {
  position: sticky;
  top: 0;
  height: 100vh;
  overflow-y: auto;
  background: linear-gradient(180deg, var(--sa-color-primary) 0%, var(--sa-color-primary-deep) 100%);
  color: #f6fbff;
  padding: 28px 20px;
}

.brand {
  margin-bottom: 28px;
}

.brand h1 {
  margin: 0 0 8px;
  font-size: 22px;
}

.brand p {
  margin: 0;
  color: rgba(246, 251, 255, 0.76);
  line-height: 1.7;
  font-size: 13px;
}

.nav {
  display: grid;
  gap: 10px;
}

.nav-item {
  padding: 12px 14px;
  border-radius: var(--sa-radius-soft);
  color: rgba(246, 251, 255, 0.88);
  transition: background-color 0.2s ease, transform 0.2s ease;
}

.nav-item:hover,
.nav-item.router-link-active {
  background: rgba(255, 255, 255, 0.12);
  transform: translateX(2px);
}

.main-content {
  display: grid;
  grid-template-rows: auto 1fr;
  min-width: 0;
  min-height: 100vh;
}

.topbar {
  padding: 24px 28px 12px;
  display: flex;
  justify-content: space-between;
  gap: 16px;
  align-items: center;
}

.topbar strong {
  display: block;
  font-size: 22px;
  margin-bottom: 6px;
}

.topbar p {
  margin: 0;
  color: var(--sa-color-text-secondary);
  line-height: 1.7;
}

.user-box {
  display: flex;
  align-items: center;
  gap: 12px;
}

.user-meta {
  display: grid;
  text-align: right;
}

.user-name {
  color: var(--sa-color-primary-deep);
  font-weight: 700;
}

.user-role {
  color: var(--sa-color-text-secondary);
  font-size: 13px;
}

.page-container {
  min-width: 0;
}

@media (max-width: 960px) {
  .app-shell {
    grid-template-columns: 1fr;
  }

  .sidebar {
    padding: 20px;
  }

  .nav {
    grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
  }

  .topbar {
    flex-direction: column;
    align-items: flex-start;
  }
}
</style>
