<template>
  <el-breadcrumb class="sa-breadcrumb" separator="/">
    <el-breadcrumb-item to="/security/overview">安全业务</el-breadcrumb-item>
    <el-breadcrumb-item
      v-for="item in breadcrumbItems"
      :key="item.label"
      :to="item.to"
    >
      {{ item.label }}
    </el-breadcrumb-item>
  </el-breadcrumb>
</template>

<script setup>
import { computed } from 'vue'
import { useRoute } from 'vue-router'

const route = useRoute()

const breadcrumbItems = computed(() => {
  const path = route.path

  if (path.startsWith('/security/task/')) {
    return [
      { label: '检测任务', to: '/security/task' },
      { label: '任务详情' },
    ]
  }

  if (path.startsWith('/security/alert/')) {
    return [
      { label: '预警中心', to: '/security/alert' },
      { label: '预警详情' },
    ]
  }

  const mapping = {
    '/security/overview': [{ label: '态势总览' }],
    '/security/task': [{ label: '检测任务' }],
    '/security/history': [{ label: '检测历史' }],
    '/security/monitor': [{ label: '实时流量监控' }],
    '/security/user-monitor-panel': [{ label: '用户实时流量面板' }],
    '/security/alert': [{ label: '预警中心' }],
    '/security/config': [{ label: '系统配置' }],
    '/system/users': [{ label: '用户管理' }],
    '/system/audit-logs': [{ label: '操作审计' }],
  }

  return mapping[path] || []
})
</script>

<style scoped>
.sa-breadcrumb {
  margin-bottom: 14px;
}
</style>
