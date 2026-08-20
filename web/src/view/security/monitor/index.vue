<template>
  <section class="sa-page">
    <SecurityBreadcrumb />

    <header class="sa-page-header">
      <div>
        <h1>实时流量监控</h1>
        <p>选择网卡后即可持续监听当前主机相关流量，每 5 秒完成一轮分析，可手动开始或暂停监控。</p>
      </div>
      <el-tag :type="monitorRunning ? 'danger' : 'info'">{{ monitorRunning ? '监控运行中' : '监控未启动' }}</el-tag>
    </header>

    <el-card class="sa-panel" shadow="never">
      <el-alert
        class="sa-table-alert"
        type="info"
        :closable="false"
        title="实时监控不会写入检测历史，也不绑定任务；命中预警时会写入预警中心并弹出简略提示。"
      />

      <el-form v-loading="initializing" :model="form" label-width="120px">
        <el-form-item label="监听网卡">
          <el-select
            v-model="form.interfaceName"
            filterable
            clearable
            placeholder="请选择需要监听的网卡"
            :loading="initializing"
            :disabled="monitorRunning"
          >
            <el-option
              v-for="item in flowInterfaceOptions"
              :key="item.name"
              :label="buildFlowInterfaceLabel(item)"
              :value="item.name"
            />
          </el-select>
        </el-form-item>
        <el-form-item label="刷新频率">
          <el-tag>5 秒 / 轮</el-tag>
        </el-form-item>
        <el-form-item>
          <el-button
            type="primary"
            :loading="starting"
            :disabled="monitorRunning || !form.interfaceName.trim()"
            @click="handleStart"
          >
            开始监控
          </el-button>
          <el-button
            :loading="stopping"
            :disabled="!monitorRunning || !session.sessionId"
            @click="handleStop"
          >
            暂停监控
          </el-button>
        </el-form-item>
      </el-form>
    </el-card>

    <el-alert
      v-if="errorMessage"
      class="sa-panel"
      type="error"
      :closable="false"
      :title="errorMessage"
    />

    <el-card v-if="session.sessionId" class="sa-panel" shadow="never">
      <template #header>监控状态</template>
      <el-descriptions :column="1" border>
        <el-descriptions-item label="会话 ID">{{ session.sessionId }}</el-descriptions-item>
        <el-descriptions-item label="监控状态">{{ session.status || '-' }}</el-descriptions-item>
        <el-descriptions-item label="最近分析状态">{{ session.lastAnalysisStatus || '-' }}</el-descriptions-item>
        <el-descriptions-item label="监听网卡">{{ session.interfaceName || '-' }}</el-descriptions-item>
        <el-descriptions-item label="摘要">{{ session.summary || '-' }}</el-descriptions-item>
        <el-descriptions-item label="解析器">{{ session.parserName || '-' }}</el-descriptions-item>
        <el-descriptions-item label="启动时间">{{ session.startedAt || '-' }}</el-descriptions-item>
        <el-descriptions-item label="最近分析时间">{{ session.lastAnalyzedAt || '-' }}</el-descriptions-item>
        <el-descriptions-item label="暂停时间">{{ session.finishedAt || '-' }}</el-descriptions-item>
      </el-descriptions>
    </el-card>

    <div v-if="session.sessionId" class="monitor-grid">
      <el-card class="sa-panel" shadow="never">
        <template #header>实时指标</template>
        <div class="metric-list">
          <div class="metric-item">
            <span>报文数</span>
            <strong>{{ session.packetCount || 0 }}</strong>
          </div>
          <div class="metric-item">
            <span>字节数</span>
            <strong>{{ formatByteCount(session.byteCount) }}</strong>
          </div>
          <div class="metric-item">
            <span>会话数</span>
            <strong>{{ session.conversationCount || 0 }}</strong>
          </div>
          <div class="metric-item">
            <span>行为风险</span>
            <strong>{{ session.behaviorRiskScore || 0 }}</strong>
          </div>
          <div class="metric-item">
            <span>峰值 PPS</span>
            <strong>{{ session.peakPps || 0 }}</strong>
          </div>
          <div class="metric-item">
            <span>扫描评分</span>
            <strong>{{ session.scanScore || 0 }}</strong>
          </div>
        </div>
      </el-card>

      <el-card class="sa-panel" shadow="never">
        <template #header>协议与应用信号</template>
        <el-descriptions :column="1" border>
          <el-descriptions-item label="协议分布">
            <pre class="json-block">{{ formatJson(session.protocolDistribution) }}</pre>
          </el-descriptions-item>
          <el-descriptions-item label="DNS Top">
            <pre class="json-block">{{ formatJson(session.dnsTopQuestions) }}</pre>
          </el-descriptions-item>
          <el-descriptions-item label="HTTP Host">
            <pre class="json-block">{{ formatJson(session.httpHostHints) }}</pre>
          </el-descriptions-item>
          <el-descriptions-item label="TLS 握手">
            <pre class="json-block">{{ formatJson(session.tlsHandshakeHints) }}</pre>
          </el-descriptions-item>
          <el-descriptions-item label="应用信号">
            <pre class="json-block">{{ formatJson(session.applicationSignals) }}</pre>
          </el-descriptions-item>
        </el-descriptions>
      </el-card>

      <el-card class="sa-panel" shadow="never">
        <template #header>行为侧写与预警</template>
        <el-descriptions :column="1" border>
          <el-descriptions-item label="方向性指标">
            <pre class="json-block">{{ formatJson(session.directionalityIndicators) }}</pre>
          </el-descriptions-item>
          <el-descriptions-item label="端口密度指标">
            <pre class="json-block">{{ formatJson(session.portDensityIndicators) }}</pre>
          </el-descriptions-item>
          <el-descriptions-item label="载荷熵指标">
            <pre class="json-block">{{ formatJson(session.payloadEntropyIndicators) }}</pre>
          </el-descriptions-item>
          <el-descriptions-item label="最新预警">
            <div v-if="session.latestAlert" class="alert-brief">
              <el-tag :type="getAlertLevelTag(session.latestAlert.alertLevel)">
                {{ getRiskLevelText(session.latestAlert.alertLevel) }}
              </el-tag>
              <span>{{ session.latestAlert.alertTitle }}</span>
              <span class="alert-meta">{{ session.latestAlert.createdAt }}</span>
            </div>
            <span v-else>-</span>
          </el-descriptions-item>
          <el-descriptions-item label="调试载荷">
            <pre class="json-block">{{ formatJson(session.debugPayload) }}</pre>
          </el-descriptions-item>
        </el-descriptions>
      </el-card>
    </div>
  </section>
</template>

<script setup>
import { computed, onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'

import SecurityBreadcrumb from '../../../components/security/SecurityBreadcrumb.vue'
import { getFlowInterfaces, getSecurityConfig } from '../../../api/securityConfig'
import {
  getCurrentFlowMonitorSession,
  getFlowMonitorSession,
  startFlowMonitorSession,
  stopFlowMonitorSession,
} from '../../../api/securityFlowMonitor'
import { getAlertLevelTag, getRiskLevelText } from '../../../constants/security'

const router = useRouter()
const starting = ref(false)
const stopping = ref(false)
const initializing = ref(false)
const errorMessage = ref('')
const session = ref({})
const flowInterfaceOptions = ref([])
const lastPresentedAlertId = ref(0)

let pollTimer = null
let pollingStopped = false

const form = reactive({
  interfaceName: '',
})

const monitorRunning = computed(() => session.value?.status === 'RUNNING')

const buildFlowInterfaceLabel = (item) => {
  const parts = [item.name]
  if (item.interfaceDescription) {
    parts.push(item.interfaceDescription)
  }
  if (item.status) {
    parts.push(`状态：${item.status}`)
  }
  return parts.join(' / ')
}

const applyMonitorDefaults = (config, interfaces) => {
  if (!config) {
    return
  }
  const configuredInterfaceName = (config.flowInterfaceName || '').trim()
  if (!configuredInterfaceName) {
    return
  }
  const matched = interfaces.find((item) => item.name === configuredInterfaceName)
  form.interfaceName = matched ? matched.name : ''
}

// 初始化：并行拉取安全配置、网卡列表与当前进行中的会话；
// 若存在运行中的会话则自动恢复轮询，实现刷新页面后监控状态不丢
const loadMonitorDefaults = async () => {
  initializing.value = true
  errorMessage.value = ''
  try {
    const [configResp, interfacesResp, currentSessionResp] = await Promise.all([
      getSecurityConfig(),
      getFlowInterfaces(),
      getCurrentFlowMonitorSession(),
    ])
    flowInterfaceOptions.value = interfacesResp.data.data || []
    applyMonitorDefaults(configResp.data.data, flowInterfaceOptions.value)
    const runningSession = currentSessionResp.data.data
    if (runningSession?.sessionId) {
      session.value = runningSession
      form.interfaceName = runningSession.interfaceName || form.interfaceName
      schedulePolling()
    }
  } catch (error) {
    flowInterfaceOptions.value = []
    errorMessage.value = error.message
  } finally {
    initializing.value = false
  }
}

const formatJson = (value) => {
  if (!value || (typeof value === 'object' && !Object.keys(value).length)) {
    return '-'
  }
  try {
    return JSON.stringify(value, null, 2)
  } catch (error) {
    return String(value)
  }
}

const formatByteCount = (value) => {
  if (value === 0) return '0 B'
  if (!value) return '-'
  if (value >= 1024 * 1024) return `${(value / (1024 * 1024)).toFixed(2)} MB`
  if (value >= 1024) return `${(value / 1024).toFixed(2)} KB`
  return `${value} B`
}

const clearPolling = () => {
  pollingStopped = true
  if (pollTimer) {
    window.clearTimeout(pollTimer)
    pollTimer = null
  }
}

// 5 秒轮询：用 setTimeout 递归实现（而非 setInterval），保证上一轮请求完成后才开始下一轮，
// 避免网络慢时请求堆积；pollingStopped 标志用于组件卸载后停止自调度
const schedulePolling = () => {
  if (pollingStopped) {
    return
  }
  clearPolling()
  pollingStopped = false
  if (!monitorRunning.value || !session.value?.sessionId) {
    return
  }
  pollTimer = window.setTimeout(async () => {
    await refreshSession()
    if (!pollingStopped) {
      schedulePolling()
    }
  }, 5000)
}

// 弹出最新预警：按 alertId 去重，只在出现"新预警"时弹一次，避免每轮轮询重复打断；
// 用户点"已知"后跳转到预警详情
const presentLatestAlert = async (latestAlert) => {
  if (!latestAlert?.alertId || latestAlert.alertId === lastPresentedAlertId.value) {
    return
  }
  lastPresentedAlertId.value = latestAlert.alertId
  try {
    await ElMessageBox.confirm(
      `${latestAlert.alertTitle}\n${latestAlert.alertContent}`,
      `实时预警 / ${getRiskLevelText(latestAlert.alertLevel)}`,
      {
        confirmButtonText: '已知',
        cancelButtonText: '忽略',
        type: 'warning',
        distinguishCancelAndClose: true,
      }
    )
    router.push(`/security/alert/${latestAlert.alertId}`)
  } catch (error) {
    // 忽略关闭和取消行为
  }
}

// 刷新监控会话数据并检查是否产生新预警；请求异常时停止轮询防止持续报错
const refreshSession = async () => {
  if (!session.value?.sessionId) {
    return
  }
  try {
    const resp = await getFlowMonitorSession(session.value.sessionId)
    session.value = resp.data.data
    await presentLatestAlert(session.value.latestAlert)
  } catch (error) {
    errorMessage.value = error.message
    clearPolling()
  }
}

// 启动监控：调用后端创建会话，成功后重置预警去重标记并进入轮询
const handleStart = async () => {
  if (!form.interfaceName.trim()) {
    ElMessage.error('请选择需要监听的网卡')
    return
  }

  starting.value = true
  errorMessage.value = ''
  try {
    const resp = await startFlowMonitorSession({
      interfaceName: form.interfaceName.trim(),
    })
    session.value = resp.data.data
    lastPresentedAlertId.value = 0
    ElMessage.success('实时流量监控已启动')
    schedulePolling()
  } catch (error) {
    errorMessage.value = error.message
    ElMessage.error(error.message)
  } finally {
    starting.value = false
  }
}

// 暂停监控：停止会话并立即清空轮询定时器，避免暂停后仍持续请求
const handleStop = async () => {
  if (!session.value?.sessionId) return
  stopping.value = true
  errorMessage.value = ''
  try {
    const resp = await stopFlowMonitorSession(session.value.sessionId)
    session.value = resp.data.data
    clearPolling()
    ElMessage.success('实时流量监控已暂停')
  } catch (error) {
    errorMessage.value = error.message
    ElMessage.error(error.message)
  } finally {
    stopping.value = false
  }
}

onMounted(loadMonitorDefaults)
onBeforeUnmount(clearPolling)
</script>

<style scoped>
.monitor-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
  gap: 16px;
}

.metric-list {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 12px;
}

.metric-item {
  padding: 12px;
  border-radius: 10px;
  background: #f7f8fa;
  display: grid;
  gap: 6px;
}

.metric-item span {
  color: #5b6b7a;
  font-size: 13px;
}

.metric-item strong {
  color: #12344d;
  font-size: 20px;
}

.json-block {
  margin: 0;
  white-space: pre-wrap;
  word-break: break-all;
  font-size: 12px;
  line-height: 1.5;
}

.alert-brief {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  align-items: center;
}

.alert-meta {
  color: #6b7a89;
  font-size: 12px;
}
</style>
