<template>
  <section class="sa-page">
    <SecurityBreadcrumb />

    <header class="sa-page-header">
      <div>
        <h1>操作审计</h1>
        <p>查看登录、任务创建、配置修改、流量会话和告警发送相关的关键操作记录。</p>
      </div>
      <el-tag type="warning">管理员</el-tag>
    </header>

    <el-card class="sa-panel" shadow="never">
      <el-form :inline="true" :model="filters">
        <el-form-item label="分类">
          <el-select v-model="filters.category" clearable>
            <el-option v-for="item in categories" :key="item" :label="item" :value="item" />
          </el-select>
        </el-form-item>
        <el-form-item label="状态">
          <el-select v-model="filters.status" clearable>
            <el-option label="SUCCESS" value="SUCCESS" />
            <el-option label="FAILED" value="FAILED" />
            <el-option label="STOPPED" value="STOPPED" />
          </el-select>
        </el-form-item>
        <el-form-item label="操作人">
          <el-input v-model="filters.actor" clearable />
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="loadData">查询</el-button>
        </el-form-item>
      </el-form>
    </el-card>

    <el-card class="sa-panel" shadow="never">
      <el-table v-loading="loading" :data="items" border>
        <el-table-column prop="category" label="分类" min-width="120" />
        <el-table-column prop="action" label="动作" min-width="180" />
        <el-table-column prop="actor" label="操作人" min-width="120" />
        <el-table-column prop="status" label="状态" min-width="120" />
        <el-table-column prop="targetLabel" label="目标" min-width="180" />
        <el-table-column prop="summary" label="摘要" min-width="320" show-overflow-tooltip />
        <el-table-column prop="createdAt" label="时间" min-width="180" />
      </el-table>
    </el-card>
  </section>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue'

import SecurityBreadcrumb from '../../../components/security/SecurityBreadcrumb.vue'
import { getAuditLogs } from '../../../api/securityAudit'

const loading = ref(false)
const items = ref([])
const categories = ref([])
const filters = reactive({
  category: '',
  status: '',
  actor: '',
})

const loadData = async () => {
  loading.value = true
  try {
    const resp = await getAuditLogs({ ...filters, page: 1, pageSize: 50 })
    items.value = resp.data.data.items || []
    categories.value = resp.data.data.categories || []
  } finally {
    loading.value = false
  }
}

onMounted(loadData)
</script>
