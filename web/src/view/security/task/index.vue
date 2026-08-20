<template>
  <section class="sa-page">
    <SecurityBreadcrumb />

    <header class="sa-page-header">
      <div>
        <h1>{{ content.title }}</h1>
        <p>{{ content.description }}</p>
      </div>
      <el-tag type="primary">{{ content.badge }}</el-tag>
    </header>

    <el-card class="sa-panel" shadow="never">
      <template #header>{{ content.createCardTitle }}</template>

      <el-alert
        v-if="!userStore.canCreateTask"
        class="sa-table-alert"
        type="info"
        :closable="false"
        :title="content.readonlyHint"
      />

      <el-form
        ref="formRef"
        :model="form"
        :rules="formRules"
        inline
        @submit.prevent="submitTask"
      >
        <el-form-item :label="content.targetIpLabel" prop="targetIp">
          <el-input
            v-model="form.targetIp"
            :placeholder="content.targetIpPlaceholder"
            :disabled="!userStore.canCreateTask"
            @keyup.enter="submitTask"
          />
        </el-form-item>
        <el-form-item>
          <el-button
            :loading="submitting"
            :disabled="!userStore.canCreateTask"
            type="primary"
            native-type="submit"
            @click="submitTask"
          >
            {{ content.submitButton }}
          </el-button>
        </el-form-item>
      </el-form>
    </el-card>

    <el-card class="sa-panel list-panel" shadow="never">
      <template #header>{{ content.listCardTitle }}</template>

      <!-- 列表统计：总任务数/高危/严重/失败，基于当前已加载列表计算（useSecurityListStats） -->
      <div class="stats-toolbar">
        <el-tag>{{ content.quickStats.total }}：{{ taskStats.total }}</el-tag>
        <el-tag type="warning">{{ content.quickStats.highRisk }}：{{ taskStats.highRisk }}</el-tag>
        <el-tag type="danger">{{ content.quickStats.criticalRisk }}：{{ taskStats.criticalRisk }}</el-tag>
        <el-tag type="info">{{ content.quickStats.failed }}：{{ taskStats.failed }}</el-tag>
      </div>

      <el-alert
        class="sa-table-alert"
        type="info"
        :closable="false"
        :title="`${content.activeFilterPrefix}${activeFilterText}`"
      />

      <!-- 筛选工具栏：按目标 IP / 任务状态 / 风险等级 / 排序方式过滤，任一条件变化即重新请求 -->
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
          v-model="filters.taskStatus"
          class="filter-item"
          clearable
          :placeholder="content.statusPlaceholder"
          @change="handleFilter"
        >
          <el-option label="待执行" value="PENDING" />
          <el-option label="执行中" value="RUNNING" />
          <el-option label="已完成" value="SUCCESS" />
          <el-option label="执行失败" value="FAILED" />
        </el-select>
        <el-select
          v-model="filters.riskLevel"
          class="filter-item"
          clearable
          :placeholder="content.riskLevelPlaceholder"
          @change="handleFilter"
        >
          <el-option label="低风险" value="LOW" />
          <el-option label="中风险" value="MEDIUM" />
          <el-option label="高风险" value="HIGH" />
          <el-option label="严重风险" value="CRITICAL" />
        </el-select>
        <el-select
          v-model="filters.sortOption"
          class="filter-item"
          :placeholder="content.sortPlaceholder"
          @change="handleFilter"
        >
          <el-option label="按最新创建排序" value="createdAtDesc" />
          <el-option label="按最早创建排序" value="createdAtAsc" />
          <el-option label="按评分从高到低排序" value="scoreValueDesc" />
          <el-option label="按评分从低到高排序" value="scoreValueAsc" />
          <el-option label="按风险从高到低排序" value="riskLevelDesc" />
          <el-option label="按风险从低到高排序" value="riskLevelAsc" />
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
      <el-table v-loading="loading" :data="tasks" border :empty-text="content.emptyText">
        <el-table-column prop="taskId" :label="content.columns.taskId" width="100" />
        <el-table-column prop="taskNo" :label="content.columns.taskNo" min-width="180" />
        <el-table-column prop="targetIp" :label="content.columns.targetIp" min-width="150" />
        <el-table-column :label="content.columns.riskLevel" width="120">
          <template #default="{ row }">
            <el-tag :type="getRiskLevelTag(row.riskLevel)" class="sa-status-tag">{{ getRiskLevelText(row.riskLevel) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column :label="content.columns.taskStatus" width="120">
          <template #default="{ row }">
            <el-tag :type="getTaskStatusTag(row.taskStatus)">{{ getTaskStatusText(row.taskStatus) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="scoreValue" :label="content.columns.scoreValue" width="100" />
        <el-table-column prop="createdAt" :label="content.columns.createdAt" min-width="180" />
        <el-table-column :label="content.columns.action" width="120" fixed="right">
          <template #default="{ row }">
            <el-button link type="primary" @click="openDetail(row.taskId)">{{ content.detailAction }}</el-button>
          </template>
        </el-table-column>
      </el-table>

      <div class="sa-pager">
        <el-pagination
          background
          layout="total, sizes, prev, pager, next"
          :current-page="pagination.page"
          :page-size="pagination.pageSize"
          :page-sizes="[10, 20, 50]"
          :total="pagination.total"
          @current-change="handlePageChange"
          @size-change="handlePageSizeChange"
        />
      </div>
    </el-card>
  </section>
</template>

<script setup>
import { onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { useRouter } from 'vue-router'

import { createSecurityTask, getSecurityTaskList } from '../../../api/securityTask'
import SecurityBreadcrumb from '../../../components/security/SecurityBreadcrumb.vue'
import { useSecurityListStats } from '../../../hooks/useSecurityListStats'
import {
  getRiskLevelTag,
  getRiskLevelText,
  getTaskStatusTag,
  getTaskStatusText,
} from '../../../constants/security'
import { securityPageContent } from '../../../constants/securityContent'
import { useUserStore } from '../../../pinia/modules/user'

const router = useRouter()
const userStore = useUserStore()
const content = securityPageContent.task
const formRef = ref()
const form = reactive({
  targetIp: '',
})
const filters = reactive({
  targetIp: '',
  taskStatus: '',
  riskLevel: '',
  sortOption: 'createdAtDesc',
})

const tasks = ref([])
const loading = ref(false)
const submitting = ref(false)
const errorMessage = ref('')
let taskPollingTimer = null
let taskPollingInFlight = false
const pagination = reactive({
  page: 1,
  pageSize: 10,
  total: 0,
})

const sortOptionMap = {
  createdAtDesc: { sortBy: 'createdAt', sortOrder: 'desc', label: '按最新创建排序' },
  createdAtAsc: { sortBy: 'createdAt', sortOrder: 'asc', label: '按最早创建排序' },
  scoreValueDesc: { sortBy: 'scoreValue', sortOrder: 'desc', label: '按评分从高到低排序' },
  scoreValueAsc: { sortBy: 'scoreValue', sortOrder: 'asc', label: '按评分从低到高排序' },
  riskLevelDesc: { sortBy: 'riskLevel', sortOrder: 'desc', label: '按风险从高到低排序' },
  riskLevelAsc: { sortBy: 'riskLevel', sortOrder: 'asc', label: '按风险从低到高排序' },
}

const getCurrentSortOption = () => sortOptionMap[filters.sortOption] || sortOptionMap.createdAtDesc

const { stats: taskStats, activeFilterText } = useSecurityListStats(
  tasks,
  pagination,
  filters,
  (items, pager) => ({
    total: pager.total,
    highRisk: items.filter((item) => item.riskLevel === 'HIGH').length,
    criticalRisk: items.filter((item) => item.riskLevel === 'CRITICAL').length,
    failed: items.filter((item) => item.taskStatus === 'FAILED').length,
  }),
  (currentFilters) => {
    const parts = []
    if (currentFilters.targetIp.trim()) {
      parts.push(`目标 IP：${currentFilters.targetIp.trim()}`)
    }
    if (currentFilters.taskStatus) {
      parts.push(`任务状态：${getTaskStatusText(currentFilters.taskStatus)}`)
    }
    if (currentFilters.riskLevel) {
      parts.push(`风险等级：${getRiskLevelText(currentFilters.riskLevel)}`)
    }
    if (currentFilters.sortOption !== 'createdAtDesc') {
      parts.push(`排序：${getCurrentSortOption().label}`)
    }
    return parts.length ? parts.join('，') : content.noFilterText
  }
)

// 校验 IPv4/IPv6 地址：IPv4 用点分十进制每段 0-255 的精确正则，IPv6 覆盖完整/缩写/压缩多种写法，
// 与 isValidDomain 一起构成创建任务前的输入校验，避免非法输入直接提交后端
const isValidIP = (value) => {
  const input = value.trim()
  if (!input) {
    return false
  }

  const ipv4Segment = '(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)'
  const ipv4Pattern = new RegExp(`^(${ipv4Segment}\\.){3}${ipv4Segment}$`)
  const ipv6Pattern = /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(([0-9a-fA-F]{1,4}:){1,7}:)|(:([0-9a-fA-F]{1,4}:){1,7})|(([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4})|(([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2})|(([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3})|(([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4})|(([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5})|([0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6}))|(:(:[0-9a-fA-F]{1,4}){1,7}|:))$/
  return ipv4Pattern.test(input) || ipv6Pattern.test(input)
}

// 校验域名：总长不超过 253、不能以点开头结尾、至少两段、每段符合主机名规范
const isValidDomain = (value) => {
  const input = value.trim()
  if (!input || input.length > 253 || input.startsWith('.') || input.endsWith('.')) {
    return false
  }
  const labels = input.split('.')
  if (labels.length < 2) {
    return false
  }
  return labels.every((label) => /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(label))
}

// 自定义表单校验器：目标输入必须是合法 IP 或域名，否则在失焦时给出对应提示
const validateTargetInput = (rule, value, callback) => {
  const input = (value || '').trim()
  if (!input) {
    callback(new Error(content.createWarning))
    return
  }
  if (!isValidIP(input) && !isValidDomain(input)) {
    callback(new Error(content.createInvalidWarning))
    return
  }
  callback()
}

// 创建任务表单仅校验目标输入字段，使用上面的自定义校验器
const formRules = {
  targetIp: [{ validator: validateTargetInput, trigger: 'blur' }],
}

// 判断当前列表里是否存在待执行/执行中的任务：存在才需要轮询刷新状态
const hasActiveTask = () => tasks.value.some((item) => ['PENDING', 'RUNNING'].includes(item.taskStatus))

// 停止轮询并清空定时器；组件卸载前调用，避免页面离开后仍持续请求
const stopTaskPolling = () => {
  if (!taskPollingTimer) {
    return
  }
  window.clearInterval(taskPollingTimer)
  taskPollingTimer = null
}

// 启动 3 秒轮询：有进行中任务时静默刷新列表；若上一次请求还在途则跳过本轮，避免请求堆积
const startTaskPolling = () => {
  if (taskPollingTimer) {
    return
  }
  taskPollingTimer = window.setInterval(() => {
    if (loading.value || submitting.value || taskPollingInFlight) {
      return
    }
    loadTasks({ silent: true })
  }, 3000)
}

// 根据是否有进行中任务，自动开启或停止轮询（有则启动、无则停止）
const syncTaskPolling = () => {
  if (hasActiveTask()) {
    startTaskPolling()
    return
  }
  stopTaskPolling()
}

// 拉取任务列表：根据筛选条件与排序选项请求分页数据；silent 用于轮询时静默刷新不闪 loading
const loadTasks = async (options = {}) => {
  const silent = options.silent === true
  if (!silent) {
    loading.value = true
  } else {
    taskPollingInFlight = true
  }
  errorMessage.value = ''
  try {
    const sortOption = getCurrentSortOption()
    const resp = await getSecurityTaskList({
      page: pagination.page,
      pageSize: pagination.pageSize,
      targetIp: filters.targetIp.trim(),
      taskStatus: filters.taskStatus,
      riskLevel: filters.riskLevel,
      sortBy: sortOption.sortBy,
      sortOrder: sortOption.sortOrder,
    })
    tasks.value = resp.data.data.items || []
    pagination.total = resp.data.data.total || 0
    syncTaskPolling()
  } catch (error) {
    errorMessage.value = error.message
  } finally {
    if (!silent) {
      loading.value = false
    } else {
      taskPollingInFlight = false
    }
  }
}

// 创建检测任务：先校验表单与权限，成功后清空输入、回到第一页重新加载列表
const submitTask = async () => {
  if (submitting.value) {
    return
  }

  if (!userStore.canCreateTask) {
    ElMessage.warning(content.readonlyHint)
    return
  }

  try {
    await formRef.value?.validate()
  } catch {
    return
  }

  submitting.value = true
  try {
    await createSecurityTask({
      targetIp: form.targetIp.trim(),
      requestedBy: userStore.username,
    })
    ElMessage.success(content.createSuccess)
    form.targetIp = ''
    formRef.value?.clearValidate('targetIp')
    pagination.page = 1
    await loadTasks()
  } catch (error) {
    ElMessage.error(error.message)
  } finally {
    submitting.value = false
  }
}

// 跳转到任务详情页，携带任务 ID 作为路由参数
const openDetail = (taskId) => {
  router.push(`/security/task/${taskId}`)
}

const handlePageChange = (page) => {
  pagination.page = page
  loadTasks()
}

const handlePageSizeChange = (pageSize) => {
  pagination.page = 1
  pagination.pageSize = pageSize
  loadTasks()
}

const handleFilter = () => {
  pagination.page = 1
  loadTasks()
}

const handleReset = () => {
  filters.targetIp = ''
  filters.taskStatus = ''
  filters.riskLevel = ''
  filters.sortOption = 'createdAtDesc'
  pagination.page = 1
  pagination.pageSize = 10
  loadTasks()
}

onMounted(loadTasks)
onBeforeUnmount(stopTaskPolling)
</script>

<style scoped>
.list-panel {
  margin-top: 16px;
}

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
