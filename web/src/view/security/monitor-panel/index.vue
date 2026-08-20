<template>
  <section class="sa-page">
    <SecurityBreadcrumb />

    <header class="sa-page-header">
      <div>
        <h1>用户实时流量面板</h1>
        <p>面向 Admin 和 Manager 展示 user 用户实时流量会话统计，按 5 秒刷新一次并以图形方式呈现。</p>
      </div>
      <el-tag type="warning">观察对象：{{ panel.targetDisplayName || panel.targetUsername || 'user' }}</el-tag>
    </header>

    <el-alert
      class="sa-panel"
      type="info"
      :closable="false"
      title="该面板只读展示 User 用户实时监控结果，不负责启动或停止监控。若 user 尚未启动实时监控，会显示空态。"
    />

    <el-alert
      v-if="errorMessage"
      class="sa-panel"
      type="error"
      :closable="false"
      :title="errorMessage"
    />

    <div class="stat-grid">
      <article class="stat-card">
        <span class="label">运行中会话</span>
        <strong>{{ panel.runningSessionCount || 0 }}</strong>
      </article>
      <article class="stat-card">
        <span class="label">累计会话</span>
        <strong>{{ panel.totalSessionCount || 0 }}</strong>
      </article>
      <article class="stat-card">
        <span class="label">总报文数</span>
        <strong>{{ formatNumber(panel.totalPacketCount) }}</strong>
      </article>
      <article class="stat-card">
        <span class="label">总字节数</span>
        <strong>{{ formatByteCount(panel.totalByteCount) }}</strong>
      </article>
      <article class="stat-card">
        <span class="label">最高行为分</span>
        <strong>{{ formatScore(panel.maxBehaviorRiskScore) }}</strong>
      </article>
      <article class="stat-card">
        <span class="label">最近分析时间</span>
        <strong class="time-text">{{ panel.latestAnalyzedAt || '-' }}</strong>
      </article>
    </div>

    <div class="chart-grid">
      <el-card class="sa-panel chart-card" shadow="never">
        <template #header>5 秒趋势</template>
        <div v-if="trendPoints.length" class="chart-wrapper">
          <VChart :option="trendOption" autoresize class="chart" />
        </div>
        <el-empty v-else description="当前没有 user 用户实时监控趋势数据" />
      </el-card>

      <el-card class="sa-panel chart-card" shadow="never">
        <template #header>当前协议事件</template>
        <div v-if="protocolBars.length" class="chart-wrapper">
          <VChart :option="protocolOption" autoresize class="chart" />
        </div>
        <el-empty v-else description="当前没有可展示的 DNS/HTTP/TLS 统计" />
      </el-card>
    </div>

    <el-card class="sa-panel" shadow="never">
      <template #header>会话列表</template>
      <el-table :data="panel.sessions || []" size="small" border>
        <el-table-column prop="sessionId" label="会话 ID" min-width="180" />
        <el-table-column prop="ownerDisplayName" label="用户" min-width="120">
          <template #default="{ row }">
            {{ row.ownerDisplayName || row.ownerUsername || '-' }}
          </template>
        </el-table-column>
        <el-table-column prop="interfaceName" label="网卡" min-width="120" />
        <el-table-column prop="status" label="状态" min-width="100" />
        <el-table-column prop="behaviorRiskScore" label="行为分" min-width="90">
          <template #default="{ row }">
            {{ formatScore(row.behaviorRiskScore) }}
          </template>
        </el-table-column>
        <el-table-column prop="packetCount" label="报文数" min-width="100" />
        <el-table-column prop="conversationCount" label="会话数" min-width="100" />
        <el-table-column prop="dnsEventCount" label="DNS" min-width="90" />
        <el-table-column prop="httpEventCount" label="HTTP" min-width="90" />
        <el-table-column prop="tlsEventCount" label="TLS" min-width="90" />
        <el-table-column prop="lastAnalyzedAt" label="最近分析时间" min-width="170" />
        <el-table-column prop="summary" label="摘要" min-width="260" show-overflow-tooltip />
      </el-table>
    </el-card>
  </section>
</template>

<script setup>
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import VChart from 'vue-echarts'
import { use } from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'
import { BarChart, LineChart } from 'echarts/charts'
import { GridComponent, LegendComponent, TooltipComponent } from 'echarts/components'

import SecurityBreadcrumb from '../../../components/security/SecurityBreadcrumb.vue'
import { getFlowMonitorObserverPanel } from '../../../api/securityFlowMonitor'

use([CanvasRenderer, BarChart, LineChart, GridComponent, LegendComponent, TooltipComponent])

const errorMessage = ref('')
const panel = ref({
  targetUsername: 'user',
  targetDisplayName: '',
  targetRoleCode: 'USER',
  runningSessionCount: 0,
  totalSessionCount: 0,
  totalPacketCount: 0,
  totalByteCount: 0,
  maxBehaviorRiskScore: 0,
  latestAnalyzedAt: '',
  sessions: [],
})

let timer = null
let pollingStopped = false

const trendPoints = computed(() => {
  const merged = new Map()
  for (const session of panel.value.sessions || []) {
    for (const point of session.metricTrend || []) {
      const current = merged.get(point.analyzedAt) || {
        analyzedAt: point.analyzedAt,
        packetCount: 0,
        byteCount: 0,
        conversationCount: 0,
        behaviorRiskScore: 0,
      }
      current.packetCount += point.packetCount || 0
      current.byteCount += point.byteCount || 0
      current.conversationCount += point.conversationCount || 0
      current.behaviorRiskScore = Math.max(current.behaviorRiskScore, point.behaviorRiskScore || 0)
      merged.set(point.analyzedAt, current)
    }
  }
  return Array.from(merged.values()).sort((left, right) => left.analyzedAt.localeCompare(right.analyzedAt))
})

const protocolBars = computed(() => {
  const totals = {}
  const addProtocolCount = (name, value) => {
    const protocolName = String(name || '').trim().toUpperCase()
    const count = Number(value || 0)
    if (!protocolName || count <= 0) {
      return
    }
    totals[protocolName] = (totals[protocolName] || 0) + count
  }

  for (const session of panel.value.sessions || []) {
    for (const [name, value] of Object.entries(session.protocolDistribution || {})) {
      addProtocolCount(name, value)
    }
    addProtocolCount('DNS', session.dnsEventCount)
    addProtocolCount('HTTP', session.httpEventCount)
    addProtocolCount('TLS', session.tlsEventCount)
  }

  return Object.entries(totals)
    .map(([name, value]) => ({ name, value }))
    .sort((left, right) => right.value - left.value)
    .filter((item) => item.value > 0)
})

const trendOption = computed(() => ({
  tooltip: { trigger: 'axis' },
  legend: { data: ['报文数', '行为分'] },
  xAxis: {
    type: 'category',
    data: trendPoints.value.map((item) => item.analyzedAt?.slice(11) || item.analyzedAt),
  },
  yAxis: [
    { type: 'value', name: '报文数' },
    { type: 'value', name: '行为分', min: 0, max: 100 },
  ],
  series: [
    {
      name: '报文数',
      type: 'bar',
      data: trendPoints.value.map((item) => item.packetCount),
      itemStyle: { color: '#2f6bff' },
    },
    {
      name: '行为分',
      type: 'line',
      yAxisIndex: 1,
      smooth: true,
      data: trendPoints.value.map((item) => item.behaviorRiskScore),
      itemStyle: { color: '#ff7a45' },
    },
  ],
}))

const protocolOption = computed(() => ({
  tooltip: { trigger: 'item' },
  xAxis: {
    type: 'category',
    data: protocolBars.value.map((item) => item.name),
  },
  yAxis: { type: 'value', name: '事件数' },
  series: [
    {
      type: 'bar',
      data: protocolBars.value.map((item) => item.value),
      itemStyle: {
        color: (params) => ['#3ba272', '#5470c6', '#fac858'][params.dataIndex % 3],
      },
      barWidth: 48,
    },
  ],
}))

const formatScore = (value) => {
  if (value === 0) return '0.00'
  if (!value) return '-'
  return Number(value).toFixed(2)
}

const formatNumber = (value) => {
  if (value === 0) return '0'
  if (!value) return '-'
  return `${value}`
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
  if (timer) {
    window.clearTimeout(timer)
    timer = null
  }
}

const schedulePolling = () => {
  if (pollingStopped) {
    return
  }
  clearPolling()
  pollingStopped = false
  timer = window.setTimeout(async () => {
    await loadPanel()
    if (!pollingStopped) {
      schedulePolling()
    }
  }, 5000)
}

const loadPanel = async () => {
  try {
    const resp = await getFlowMonitorObserverPanel({
      targetUsername: 'user',
      targetRoleCode: 'USER',
    })
    panel.value = resp.data.data || panel.value
    errorMessage.value = ''
  } catch (error) {
    errorMessage.value = error.message
  }
}

onMounted(async () => {
  pollingStopped = false
  await loadPanel()
  schedulePolling()
})

onBeforeUnmount(clearPolling)
</script>

<style scoped>
.stat-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 16px;
  margin: 16px 0 24px;
}

.stat-card {
  padding: 20px;
  border-radius: var(--sa-radius-card);
  background: var(--sa-color-card);
  box-shadow: 0 10px 30px var(--sa-color-shadow);
}

.label {
  display: block;
  margin-bottom: 10px;
  color: var(--sa-color-text-secondary);
}

.stat-card strong {
  font-size: 28px;
  color: var(--sa-color-primary-deep);
}

.time-text {
  font-size: 16px;
}

.chart-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
  gap: 16px;
  margin-bottom: 24px;
}

.chart-card {
  min-height: 360px;
}

.chart-wrapper {
  height: 300px;
}

.chart {
  height: 100%;
}
</style>
