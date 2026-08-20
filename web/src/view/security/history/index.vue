<template>
  <section class="sa-page">
    <SecurityBreadcrumb />

    <header class="sa-page-header">
      <div>
        <h1>{{ content.title }}</h1>
        <p>{{ content.description }}</p>
      </div>
      <el-tag>{{ content.badge }}</el-tag>
    </header>

    <el-card class="sa-panel" shadow="never">
      <div class="history-toolbar">
        <el-radio-group v-model="filterType" @change="loadHistory">
          <el-radio-button value="ALL">{{ content.typeFilter.all }}</el-radio-button>
          <el-radio-button value="TASK">{{ content.typeFilter.task }}</el-radio-button>
          <el-radio-button value="ALERT">{{ content.typeFilter.alert }}</el-radio-button>
        </el-radio-group>

        <el-input
          v-model="keyword"
          class="history-search"
          clearable
          :placeholder="content.searchPlaceholder"
          @keyup.enter="handleSearch"
          @clear="handleSearch"
        />
      </div>

      <el-alert
        v-if="errorMessage"
        class="sa-table-alert"
        type="error"
        :closable="false"
        :title="errorMessage"
      />

      <el-table v-loading="loading" :data="records" border>
        <el-table-column prop="title" :label="content.columns.title" min-width="220" />
        <el-table-column :label="content.columns.eventType" width="120">
          <template #default="{ row }">
            <span>{{ formatEventType(row.eventType) }}</span>
          </template>
        </el-table-column>
        <el-table-column prop="targetIp" :label="content.columns.targetIp" min-width="140" />
        <el-table-column prop="originalTarget" :label="content.columns.originalTarget" min-width="180">
          <template #default="{ row }">
            <span>{{ row.eventType === 'TASK' && row.originalTarget && row.originalTarget !== row.targetIp ? row.originalTarget : '-' }}</span>
          </template>
        </el-table-column>
        <el-table-column prop="taskNo" :label="content.columns.taskNo" min-width="180" />
        <el-table-column prop="sourceSummary" :label="content.columns.sourceSummary" min-width="260" show-overflow-tooltip />
        <el-table-column :label="content.columns.flowSummary" min-width="320">
          <template #default="{ row }">
            <div class="flow-summary-cell">
              <div class="flow-summary-main">
                <el-tag size="small" :type="row.flowHasRealMetrics ? 'success' : 'warning'" effect="plain">
                  {{ row.flowHasRealMetrics ? '真实承接' : '入口状态' }}
                </el-tag>
                <span>{{ row.flowSummary || '-' }}</span>
              </div>
              <div v-if="buildFlowMeta(row)" class="flow-summary-meta">{{ buildFlowMeta(row) }}</div>
            </div>
          </template>
        </el-table-column>
        <el-table-column :label="content.columns.flowTrace" min-width="170">
          <template #default="{ row }">
            <div class="flow-trace-cell">
              <el-tag size="small" :type="row.flowIsTraceable ? 'success' : 'info'" effect="plain">
                {{ row.flowIsTraceable ? '可回到任务详情追溯' : '仅保留页面入口状态' }}
              </el-tag>
              <span v-if="row.flowIsTraceable" class="flow-trace-meta">
                {{ buildTraceMeta(row) }}
              </span>
            </div>
          </template>
        </el-table-column>
        <el-table-column :label="content.columns.level" width="120">
          <template #default="{ row }">
            <el-tag :type="getRiskLevelTag(row.level)" class="sa-status-tag">{{ getRiskLevelText(row.level) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column :label="content.columns.status" width="120">
          <template #default="{ row }">
            <span>{{ formatStatus(row) }}</span>
          </template>
        </el-table-column>
        <el-table-column prop="time" :label="content.columns.time" min-width="180" />
        <el-table-column :label="content.columns.action" width="140" fixed="right">
          <template #default="{ row }">
            <el-button link type="primary" @click="openDetail(row.detailRoute)">{{ content.detailAction }}</el-button>
            <el-button
              v-if="row.eventType === 'TASK' && userStore.canCreateTask"
              link
              type="danger"
              @click="handleDelete(row)"
            >
              删除
            </el-button>
          </template>
        </el-table-column>
      </el-table>

      <el-empty v-if="!loading && records.length === 0" :description="content.empty" />

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
import { ElMessage, ElMessageBox } from 'element-plus'
import { useRouter } from 'vue-router'

import { getSecurityRecordList } from '../../../api/securityRecord'
import { deleteSecurityTask } from '../../../api/securityTask'
import SecurityBreadcrumb from '../../../components/security/SecurityBreadcrumb.vue'
import {
  getRiskLevelTag,
  getRiskLevelText,
  getSendStatusText,
  getTaskStatusText,
} from '../../../constants/security'
import { securityPageContent } from '../../../constants/securityContent'
import { useUserStore } from '../../../pinia/modules/user'

const router = useRouter()
const userStore = useUserStore()
const content = securityPageContent.history
const loading = ref(false)
const errorMessage = ref('')
const records = ref([])
const filterType = ref('ALL')
const keyword = ref('')
const pagination = reactive({
  page: 1,
  pageSize: 10,
  total: 0,
})

const formatStatus = (item) => {
  if (item.eventType === 'ALERT') {
    return getSendStatusText(item.status)
  }
  return getTaskStatusText(item.status)
}

const formatEventType = (value) => {
  if (value === 'ALERT') {
    return '预警事件'
  }
  if (value === 'TASK') {
    return '检测任务'
  }
  return value || '未知事件'
}

const formatFlowMetricValue = (value) => {
  if (value === 0) {
    return '0'
  }
  return value ? String(value) : ''
}

const buildFlowMeta = (item) => {
  const parts = []
  if (item.flowCollectionMode) {
    parts.push(`模式=${item.flowCollectionMode}`)
  }
  if (item.flowCollectionStatus) {
    parts.push(`状态=${item.flowCollectionStatus}`)
  }
  const packetCount = formatFlowMetricValue(item.flowPacketCount)
  const conversationCount = formatFlowMetricValue(item.flowConversationCount)
  const hasRealMetric = item.flowPacketCount > 0 || item.flowConversationCount > 0
  const behaviorRiskScore = hasRealMetric && (item.flowBehaviorRiskScore === 0 || item.flowBehaviorRiskScore)
    ? String(item.flowBehaviorRiskScore)
    : ''

  if (packetCount) {
    parts.push(`包=${packetCount}`)
  }
  if (conversationCount) {
    parts.push(`会话=${conversationCount}`)
  }
  if (item.flowWindowCount > 0) {
    parts.push(`窗口=${item.flowWindowCount}`)
  }
  if (item.flowHighRiskPortHits > 0) {
    parts.push(`高危命中=${item.flowHighRiskPortHits}`)
  }
  if (item.flowDNSEventCount > 0 || item.flowHTTPEventCount > 0 || item.flowTLSEventCount > 0) {
    parts.push(`DNS/HTTP/TLS=${item.flowDNSEventCount || 0}/${item.flowHTTPEventCount || 0}/${item.flowTLSEventCount || 0}`)
  }
  if (item.flowHighEntropyPacketCount > 0) {
    parts.push(`高熵=${item.flowHighEntropyPacketCount}`)
  }
  if (item.flowUniqueTargetPortCount > 0) {
    parts.push(`目标端口=${item.flowUniqueTargetPortCount}`)
  }
  if (item.flowHighRiskTargetPortCount > 0) {
    parts.push(`高危端口=${item.flowHighRiskTargetPortCount}`)
  }
  if (item.flowTargetPortDensity > 0) {
    parts.push(`端口密度=${Number(item.flowTargetPortDensity).toFixed(2)}`)
  }
  if (item.flowDominantDirection) {
    parts.push(`主方向=${item.flowDominantDirection}`)
  }
  if (behaviorRiskScore) {
    parts.push(`行为分=${behaviorRiskScore}`)
  }
  if (item.flowFeatureDigest) {
    parts.push(`digest=${item.flowFeatureDigest}`)
  }
  return parts.join(' / ')
}

const buildTraceMeta = (item) => {
  const parts = []
  if (item.flowHistorySourceTable) {
    parts.push(`历史=${item.flowHistorySourceTable}`)
  }
  if (item.flowEvidenceSourceTable) {
    parts.push(`证据=${item.flowEvidenceSourceTable}`)
  }
  return parts.join(' / ')
}

const loadHistory = async () => {
  loading.value = true
  errorMessage.value = ''
  try {
    const resp = await getSecurityRecordList({
      page: pagination.page,
      pageSize: pagination.pageSize,
      eventType: filterType.value,
      keyword: keyword.value.trim(),
    })
    records.value = resp.data.data.items || []
    pagination.total = resp.data.data.total || 0
  } catch (error) {
    errorMessage.value = error.message
  } finally {
    loading.value = false
  }
}

const handleSearch = () => {
  pagination.page = 1
  loadHistory()
}

const handlePageChange = (page) => {
  pagination.page = page
  loadHistory()
}

const openDetail = (path) => {
  router.push(path)
}

const handleDelete = async (row) => {
  try {
    await ElMessageBox.confirm(`确认删除检测任务 ${row.taskNo} 吗？删除后其历史、预警、评分和流量记录将一并清理。`, '删除确认', {
      type: 'warning',
      confirmButtonText: '确认删除',
      cancelButtonText: '取消',
    })
  } catch {
    return
  }

  try {
    await deleteSecurityTask(row.id)
    ElMessage.success('检测任务已删除')
    if (records.value.length === 1 && pagination.page > 1) {
      pagination.page -= 1
    }
    await loadHistory()
  } catch (error) {
    ElMessage.error(error.message)
  }
}

onMounted(loadHistory)
</script>

<style scoped>
.history-toolbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 16px;
  margin-bottom: 16px;
  flex-wrap: wrap;
}

.history-search {
  width: 320px;
  max-width: 100%;
}

.flow-summary-cell {
  display: grid;
  gap: 4px;
}

.flow-summary-main {
  display: flex;
  align-items: center;
  gap: 8px;
  color: #1f2329;
  line-height: 1.5;
  flex-wrap: wrap;
}

.flow-summary-meta {
  font-size: 12px;
  color: #4e5969;
}

.flow-trace-cell {
  display: grid;
  gap: 6px;
}

.flow-trace-meta {
  font-size: 12px;
  color: #4e5969;
}
</style>
