<template>
  <section class="sa-page">
    <SecurityBreadcrumb />

    <header class="sa-page-header">
      <div>
        <h1>{{ content.title }}</h1>
        <p>{{ content.description }}</p>
      </div>
      <el-tag type="warning">{{ content.badge }}</el-tag>
    </header>

    <el-card class="sa-panel" shadow="never">
      <template #header>{{ content.listCardTitle }}</template>

      <!-- 列表统计：总预警数/严重/高危/发送失败，基于当前已加载列表计算（useSecurityListStats） -->
      <div class="stats-toolbar">
        <el-tag>{{ content.quickStats.total }}：{{ alertStats.total }}</el-tag>
        <el-tag type="danger">{{ content.quickStats.critical }}：{{ alertStats.critical }}</el-tag>
        <el-tag type="warning">{{ content.quickStats.high }}：{{ alertStats.high }}</el-tag>
        <el-tag type="info">{{ content.quickStats.failed }}：{{ alertStats.failed }}</el-tag>
      </div>

      <el-alert
        class="sa-table-alert"
        type="info"
        :closable="false"
        :title="`${content.activeFilterPrefix}${activeFilterText}`"
      />

      <!-- 筛选工具栏：按目标/标识、预警等级、发送状态过滤，任一条件变化即重新请求 -->
      <div class="filter-toolbar">
        <el-input
          v-model="filters.targetIp"
          class="filter-item"
          clearable
          :placeholder="content.filterIpPlaceholder"
          @keyup.enter="handleFilter"
          @clear="handleFilter"
        />
        <el-select
          v-model="filters.alertLevel"
          class="filter-item"
          clearable
          :placeholder="content.levelPlaceholder"
          @change="handleFilter"
        >
          <el-option label="高风险" value="HIGH" />
          <el-option label="严重风险" value="CRITICAL" />
        </el-select>
        <el-select
          v-model="filters.sendStatus"
          class="filter-item"
          clearable
          :placeholder="content.sendStatusPlaceholder"
          @change="handleFilter"
        >
          <el-option label="待发送" value="PENDING" />
          <el-option label="发送成功" value="SUCCESS" />
          <el-option label="发送失败" value="FAILED" />
        </el-select>
        <el-button type="primary" @click="handleFilter">{{ content.filterButton }}</el-button>
        <el-button @click="handleReset">{{ content.resetButton }}</el-button>
      </div>

      <el-alert
        v-if="errorMessage"
        class="sa-table-alert"
        type="error"
        :closable="false"
        :title="errorMessage"
      />
      <el-table v-loading="loading" :data="alerts" border :empty-text="content.emptyText">
        <el-table-column prop="alertId" :label="content.columns.alertId" width="100" />
        <el-table-column label="任务 / 来源" min-width="200">
          <template #default="{ row }">
            <span>{{ row.taskNo || row.sourceLabel || '-' }}</span>
          </template>
        </el-table-column>
        <el-table-column label="目标 / 标识" min-width="180">
          <template #default="{ row }">
            <span>{{ row.targetIp || row.sourceLabel || '-' }}</span>
          </template>
        </el-table-column>
        <el-table-column :label="content.columns.alertLevel" width="120">
          <template #default="{ row }">
            <el-tag :type="getAlertLevelTag(row.alertLevel)" class="sa-status-tag">{{ getRiskLevelText(row.alertLevel) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="channel" :label="content.columns.channel" width="120" />
        <el-table-column :label="content.columns.sendStatus" width="120">
          <template #default="{ row }">
            <el-tag :type="getSendStatusTag(row.sendStatus)">{{ getSendStatusText(row.sendStatus) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="createdAt" :label="content.columns.createdAt" min-width="180" />
        <el-table-column :label="content.columns.action" width="120" fixed="right">
          <template #default="{ row }">
            <el-button link type="primary" @click="openDetail(row.alertId)">{{ content.detailAction }}</el-button>
          </template>
        </el-table-column>
      </el-table>

      <div class="sa-pager">
        <el-pagination
          background
          layout="total, prev, pager, next"
          :current-page="pagination.page"
          :page-size="pagination.pageSize"
          :total="pagination.total"
          @current-change="handlePageChange"
        />
      </div>
    </el-card>
  </section>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import SecurityBreadcrumb from '../../../components/security/SecurityBreadcrumb.vue'
import { getSecurityAlertList } from '../../../api/securityAlert'
import { useSecurityListStats } from '../../../hooks/useSecurityListStats'
import {
  getAlertLevelTag,
  getRiskLevelText,
  getSendStatusTag,
  getSendStatusText,
} from '../../../constants/security'
import { securityPageContent } from '../../../constants/securityContent'

const router = useRouter()
const content = securityPageContent.alert
const alerts = ref([])
const loading = ref(false)
const errorMessage = ref('')
const filters = reactive({
  targetIp: '',
  alertLevel: '',
  sendStatus: '',
})
const pagination = reactive({
  page: 1,
  pageSize: 10,
  total: 0,
})

const { stats: alertStats, activeFilterText } = useSecurityListStats(
  alerts,
  pagination,
  filters,
  (items, pager) => ({
    total: pager.total,
    critical: items.filter((item) => item.alertLevel === 'CRITICAL').length,
    high: items.filter((item) => item.alertLevel === 'HIGH').length,
    failed: items.filter((item) => item.sendStatus === 'FAILED').length,
  }),
  (currentFilters) => {
    const parts = []
    if (currentFilters.targetIp.trim()) {
      parts.push(`目标/标识：${currentFilters.targetIp.trim()}`)
    }
    if (currentFilters.alertLevel) {
      parts.push(`预警等级：${getRiskLevelText(currentFilters.alertLevel)}`)
    }
    if (currentFilters.sendStatus) {
      parts.push(`发送状态：${getSendStatusText(currentFilters.sendStatus)}`)
    }
    return parts.length ? parts.join('；') : content.noFilterText
  }
)

// 拉取预警列表：按目标/标识、预警等级、发送状态分页查询，数据来自 getSecurityAlertList
const loadAlerts = async () => {
  loading.value = true
  errorMessage.value = ''
  try {
    const resp = await getSecurityAlertList({
      page: pagination.page,
      pageSize: pagination.pageSize,
      targetIp: filters.targetIp.trim(),
      alertLevel: filters.alertLevel,
      sendStatus: filters.sendStatus,
    })
    alerts.value = resp.data.data.items
    pagination.total = resp.data.data.total
  } catch (error) {
    errorMessage.value = error.message
  } finally {
    loading.value = false
  }
}

// 跳转到预警详情页，携带预警 ID 作为路由参数
const openDetail = (alertId) => {
  router.push(`/security/alert/${alertId}`)
}

const handlePageChange = (page) => {
  pagination.page = page
  loadAlerts()
}

const handleFilter = () => {
  pagination.page = 1
  loadAlerts()
}

const handleReset = () => {
  filters.targetIp = ''
  filters.alertLevel = ''
  filters.sendStatus = ''
  pagination.page = 1
  loadAlerts()
}

onMounted(loadAlerts)
</script>

<style scoped>
.stats-toolbar {
  display: flex;
  gap: 12px;
  flex-wrap: wrap;
  margin-bottom: 16px;
}

.filter-toolbar {
  display: flex;
  gap: 12px;
  flex-wrap: wrap;
  margin-bottom: 16px;
}

.filter-item {
  width: 220px;
  max-width: 100%;
}
</style>
