<template>
  <section class="sa-page">
    <SecurityBreadcrumb />

    <header class="sa-page-header">
      <div>
        <h1>{{ content.title }}</h1>
        <p>{{ content.description }}</p>
      </div>
      <el-tag type="danger">{{ content.badge }}</el-tag>
    </header>

    <!-- 核心指标卡：任务总数/高危/严重/预警/暴露任务等汇总数字，数据来自 getSecuritySummary -->
    <div class="stat-grid">
      <article class="stat-card">
        <span class="label">{{ content.statLabels.totalTaskCount }}</span>
        <strong>{{ summary.totalTaskCount }}</strong>
      </article>
      <article class="stat-card">
        <span class="label">{{ content.statLabels.highRiskCount }}</span>
        <strong>{{ summary.highRiskCount }}</strong>
      </article>
      <article class="stat-card">
        <span class="label">{{ content.statLabels.criticalRiskCount }}</span>
        <strong>{{ summary.criticalRiskCount }}</strong>
      </article>
      <article class="stat-card">
        <span class="label">{{ content.statLabels.alertCount }}</span>
        <strong>{{ summary.alertCount }}</strong>
      </article>
      <article class="stat-card">
        <span class="label">{{ content.statLabels.exposedTaskCount }}</span>
        <strong>{{ summary.exposedTaskCount }}</strong>
      </article>
      <article class="stat-card">
        <span class="label">{{ content.statLabels.highRiskPortTasks }}</span>
        <strong>{{ summary.highRiskPortTasks }}</strong>
      </article>
      <article class="stat-card">
        <span class="label">{{ content.statLabels.flowCollectionCount }}</span>
        <strong>{{ summary.flowCollectionCount }}</strong>
      </article>
    </div>

    <!-- 快捷入口卡片：点击跳转到检测任务 / 预警中心 -->
    <div class="quick-grid">
      <el-card class="sa-panel quick-card" shadow="never" @click="router.push('/security/task')">
        <h3>{{ content.quickLinks.taskTitle }}</h3>
        <p>{{ content.quickLinks.taskDescription }}</p>
      </el-card>
      <el-card class="sa-panel quick-card" shadow="never" @click="router.push('/security/alert')">
        <h3>{{ content.quickLinks.alertTitle }}</h3>
        <p>{{ content.quickLinks.alertDescription }}</p>
      </el-card>
    </div>

    <el-alert
      v-if="errorMessage"
      class="sa-panel"
      type="error"
      :closable="false"
      :title="errorMessage"
    />

    <el-card v-loading="loading" class="sa-panel summary-card" shadow="never">
      <template #header>{{ content.summaryTitle }}</template>
      <p class="summary-line">{{ content.summaryTextPrefix }}{{ summary.todayDetections }}</p>
      <p class="summary-note">{{ content.dataScopeText }}</p>
      <div class="source-grid">
        <div class="source-group">
          <h4>{{ content.sourceCoverage.baseInfoTitle }}</h4>
          <ul v-if="summary.baseInfoSources?.length" class="source-list">
            <li v-for="item in summary.baseInfoSources" :key="`base-${item.source}`">
              <span>{{ item.source }}</span>
              <strong>{{ item.count }}</strong>
            </li>
          </ul>
          <p v-else class="summary-note">{{ content.sourceCoverage.empty }}</p>
        </div>
        <div class="source-group">
          <h4>{{ content.sourceCoverage.reputationTitle }}</h4>
          <ul v-if="summary.reputationSources?.length" class="source-list">
            <li v-for="item in summary.reputationSources" :key="`rep-${item.source}`">
              <span>{{ item.source }}</span>
              <strong>{{ item.count }}</strong>
            </li>
          </ul>
          <p v-else class="summary-note">{{ content.sourceCoverage.empty }}</p>
        </div>
        <div class="source-group">
          <h4>{{ content.sourceCoverage.attackTitle }}</h4>
          <ul v-if="summary.attackSources?.length" class="source-list">
            <li v-for="item in summary.attackSources" :key="`atk-${item.source}`">
              <span>{{ item.source }}</span>
              <strong>{{ item.count }}</strong>
            </li>
          </ul>
          <p v-else class="summary-note">{{ content.sourceCoverage.empty }}</p>
        </div>
        <div class="source-group">
          <h4>{{ content.sourceCoverage.flowTitle }}</h4>
          <ul class="source-list">
            <li>
              <span>流量总开关</span>
              <strong>{{ summary.flowEnabled ? '已启用' : '默认关闭' }}</strong>
            </li>
            <li>
              <span>当前模式</span>
              <strong>{{ summary.activeFlowMode || '-' }}</strong>
            </li>
            <li>
              <span>近 7 天记录数</span>
              <strong>{{ summary.flowCollectionCount || 0 }}</strong>
            </li>
          </ul>
          <ul v-if="summary.flowModeDistribution?.length" class="source-list flow-mode-list">
            <li v-for="item in summary.flowModeDistribution" :key="`flow-mode-${item.mode}`">
              <span>{{ item.mode }}</span>
              <strong>{{ item.count }}</strong>
            </li>
          </ul>
        </div>
      </div>
    </el-card>

    <!-- 图表区：检测趋势折线、风险分布饼图（来自 useSecurityOverviewCharts），以及风险趋势、流量趋势两张明细表 -->
    <div class="chart-grid">
      <el-card class="sa-panel chart-card" shadow="never">
        <template #header>{{ content.trendTitle }}</template>
        <div v-if="hasTrendData" class="chart-wrapper">
          <VChart :option="trendOption" autoresize class="chart" />
        </div>
        <el-empty v-else :description="content.chartEmptyText" />
      </el-card>

      <el-card class="sa-panel chart-card" shadow="never">
        <template #header>{{ content.distributionTitle }}</template>
        <div v-if="hasDistributionData" class="chart-wrapper">
          <VChart :option="distributionOption" autoresize class="chart" />
        </div>
        <el-empty v-else :description="content.chartEmptyText" />
      </el-card>

      <el-card class="sa-panel chart-card" shadow="never">
        <template #header>{{ content.riskTrendTitle }}</template>
        <el-table :data="summary.riskTrend || []" size="small" border>
          <el-table-column prop="date" :label="content.riskTrendLabels.date" min-width="120" />
          <el-table-column prop="highRiskTaskCount" :label="content.riskTrendLabels.highRisk" min-width="120" />
          <el-table-column prop="criticalTaskCount" :label="content.riskTrendLabels.criticalRisk" min-width="120" />
        </el-table>
      </el-card>

      <el-card class="sa-panel chart-card" shadow="never">
        <template #header>{{ content.flowTrendTitle }}</template>
        <p class="summary-note flow-trend-note">
          近 7 天趋势优先展示已落库的真实窗口聚合与行为快照；若当天只有入口记录而无窗口明细，则仅保留承接记录数。
        </p>
        <el-table :data="summary.flowTrend || []" size="small" border>
          <el-table-column prop="date" :label="content.flowTrendLabels.date" min-width="120" />
          <el-table-column prop="collectionCount" :label="content.flowTrendLabels.collectionCount" min-width="110" />
          <el-table-column :label="content.flowTrendLabels.packetCount" min-width="120">
            <template #default="{ row }">
              {{ row.hasWindowMetrics ? row.packetCount : '-' }}
            </template>
          </el-table-column>
          <el-table-column label="会话聚合" min-width="120">
            <template #default="{ row }">
              {{ row.hasWindowMetrics ? row.conversationCount : '-' }}
            </template>
          </el-table-column>
          <el-table-column label="高危命中" min-width="120">
            <template #default="{ row }">
              {{ row.hasWindowMetrics ? row.highRiskPortHitCount : '-' }}
            </template>
          </el-table-column>
          <el-table-column label="DNS 事件" min-width="120">
            <template #default="{ row }">
              {{ row.hasWindowMetrics ? row.dnsEventCount : '-' }}
            </template>
          </el-table-column>
          <el-table-column label="HTTP 事件" min-width="120">
            <template #default="{ row }">
              {{ row.hasWindowMetrics ? row.httpEventCount : '-' }}
            </template>
          </el-table-column>
          <el-table-column label="TLS 事件" min-width="120">
            <template #default="{ row }">
              {{ row.hasWindowMetrics ? row.tlsEventCount : '-' }}
            </template>
          </el-table-column>
          <el-table-column :label="content.flowTrendLabels.highBehaviorRiskCount" min-width="120">
            <template #default="{ row }">
              {{ row.hasBehaviorSnapshot ? row.highBehaviorRiskCount : '-' }}
            </template>
          </el-table-column>
          <el-table-column :label="content.flowTrendLabels.trackedConversationSum" min-width="120">
            <template #default="{ row }">
              {{ row.hasBehaviorSnapshot ? row.trackedConversationSum : '-' }}
            </template>
          </el-table-column>
          <el-table-column :label="content.flowTrendLabels.averageBehaviorRisk" min-width="120">
            <template #default="{ row }">
              {{ row.hasBehaviorSnapshot ? row.averageBehaviorRisk : '-' }}
            </template>
          </el-table-column>
          <el-table-column :label="content.flowTrendLabels.highEntropyPacketCount" min-width="120">
            <template #default="{ row }">
              {{ row.hasBehaviorSnapshot ? row.highEntropyPacketCount : '-' }}
            </template>
          </el-table-column>
          <el-table-column :label="content.flowTrendLabels.averagePortDensity" min-width="120">
            <template #default="{ row }">
              {{ row.hasBehaviorSnapshot ? row.averagePortDensity : '-' }}
            </template>
          </el-table-column>
          <el-table-column :label="content.flowTrendLabels.directionalBiasCount" min-width="120">
            <template #default="{ row }">
              {{ row.hasBehaviorSnapshot ? row.directionalBiasCount : '-' }}
            </template>
          </el-table-column>
          <el-table-column label="展示口径" min-width="180">
            <template #default="{ row }">
              <div class="flow-trend-state">
                <el-tag size="small" :type="row.hasWindowMetrics ? 'success' : 'warning'" effect="plain">
                  {{ row.hasWindowMetrics ? content.flowTrendLegend.realMetrics : content.flowTrendLegend.entryOnly }}
                </el-tag>
                <el-tag size="small" :type="row.hasBehaviorSnapshot ? 'success' : 'info'" effect="plain">
                  {{ row.hasBehaviorSnapshot ? content.flowTrendLegend.behaviorReady : content.flowTrendLegend.behaviorPending }}
                </el-tag>
              </div>
            </template>
          </el-table-column>
        </el-table>
      </el-card>
    </div>

    <!-- 地理风险地图：在世界地图上标注高风险目标 IP 的散点分布，数据来自 getSecurityGeoRisk -->
    <el-card class="sa-panel geo-map-card" shadow="never">
      <template #header>{{ extraContent.geoRiskTitle }}</template>
      <div v-if="hasGeoRiskData" class="geo-map-wrapper">
        <VChart :option="geoRiskOption" autoresize class="chart" />
      </div>
      <el-empty v-else :description="extraContent.geoRiskEmpty" />
    </el-card>
  </section>
</template>

<script setup>
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { registerMap } from 'echarts/core'
import { useRouter } from 'vue-router'
import VChart from 'vue-echarts'
import worldMapSource from 'echarts-maps/world.js?raw'

import SecurityBreadcrumb from '../../../components/security/SecurityBreadcrumb.vue'
import { getSecurityGeoRisk, getSecuritySummary } from '../../../api/securityDashboard'
import { readSecurityFlowConfigSync, subscribeSecurityFlowConfigSync } from '../../../hooks/useSecurityFlowConfigSync'
import { useSecurityOverviewCharts } from '../../../hooks/useSecurityOverviewCharts'
import { securityPageContent } from '../../../constants/securityContent'
import { securityExtraContent } from '../../../constants/securityExtraContent'

// 从 echarts-maps 的 world.js 源码里用正则抠出 GeoJSON 并注册为 'world' 地图：
// 该文件不是标准模块导出，只能解析其自执行代码里的 registerMap 调用拿到地图数据
const worldMapMatch = worldMapSource.match(/echarts\.registerMap\('world',\s*([\s\S]*?)\);\s*\}\)\);?\s*$/)
if (worldMapMatch?.[1]) {
  registerMap('world', JSON.parse(worldMapMatch[1]))
}

const router = useRouter()
const content = securityPageContent.overview
const extraContent = securityExtraContent.overview
const geoRiskItems = ref([])
const summary = ref({
  totalTaskCount: 0,
  highRiskCount: 0,
  criticalRiskCount: 0,
  alertCount: 0,
  todayDetections: 0,
  exposedTaskCount: 0,
  highRiskPortTasks: 0,
  trend: [],
  riskTrend: [],
  riskDistribution: [],
  baseInfoSources: [],
  reputationSources: [],
  attackSources: [],
  flowEnabled: false,
  activeFlowMode: 'disabled',
  flowCollectionCount: 0,
  flowModeDistribution: [],
  flowTrend: [],
  flowCapabilitySummary: '',
  stableChain: [],
  enhancedSwitches: [],
  prototypeSources: [],
  boundarySummary: '',
  prototypeNote: '',
})
const loading = ref(false)
const errorMessage = ref('')
let unsubscribeFlowConfigSync = () => {}

const applyFlowConfigPreview = (payload) => {
  if (!payload) {
    return
  }
  summary.value = {
    ...summary.value,
    flowEnabled: payload.flowEnabled,
    activeFlowMode: payload.flowEnabled ? payload.flowMode : 'disabled',
  }
}

const {
  hasTrendData,
  hasDistributionData,
  trendOption,
  distributionOption,
} = useSecurityOverviewCharts(summary)

const geoRiskPointItems = computed(() => geoRiskItems.value
  .filter((item) => item.hasCoordinate)
  .map((item) => ({
    name: `${item.targetIp} / ${item.city || item.region || item.country || '未知地区'}`,
    value: [item.longitude, item.latitude],
    taskCount: item.taskCount || 0,
    alertCount: item.alertCount || 0,
    riskLevel: item.riskLevel || '-',
    targetIp: item.targetIp || '-',
  })))

const hasGeoRiskData = computed(() => geoRiskPointItems.value.length > 0)
// 地理风险地图 option：底层 world 地图 + 上层 geo scatter 散点，
// 每个点代表一个目标 IP，点大小随其关联任务数放大、颜色统一为警示红，
// 用于直观呈现高风险 IP 的全球分布，数据来自 getSecurityGeoRisk
const geoRiskOption = computed(() => ({
  backgroundColor: 'transparent',
  tooltip: {
    trigger: 'item',
    formatter: (params) => {
      const item = params.data || {}
      return [
        item.name || '-',
        `任务数：${item.taskCount || 0}`,
        `预警数：${item.alertCount || 0}`,
        `风险等级：${item.riskLevel || '-'}`,
      ].join('<br/>')
    },
  },
  geo: {
    map: 'world',
    roam: true,
    zoom: 1.12,
    center: [12, 18],
    top: 24,
    bottom: 24,
    itemStyle: {
      areaColor: '#e8eef5',
      borderColor: '#92a7bc',
      borderWidth: 0.8,
    },
    emphasis: {
      itemStyle: {
        areaColor: '#d5e2ef',
      },
      label: {
        show: false,
      },
    },
    select: {
      disabled: true,
    },
  },
  series: [
    {
      type: 'map',
      map: 'world',
      geoIndex: 0,
      silent: true,
      data: [],
    },
    {
      type: 'scatter',
      coordinateSystem: 'geo',
      symbolSize: (value, params) => Math.max(12, Math.min(36, 8 + ((params.data.taskCount || 0) * 4))),
      itemStyle: {
        color: '#d84f3f',
        borderColor: '#ffffff',
        borderWidth: 1.5,
        shadowBlur: 10,
        shadowColor: 'rgba(216, 79, 63, 0.35)',
      },
      emphasis: {
        scale: true,
        itemStyle: {
          color: '#b83227',
        },
      },
      data: geoRiskPointItems.value,
    },
  ],
}))

// 加载总览数据：并行拉取“态势汇总”与“地理风险”两个接口减少串行等待；
// 汇总对象用展开合并，保留默认字段结构，只覆盖后端实际返回的字段，避免前端空字段报错
const loadSummary = async () => {
  loading.value = true
  errorMessage.value = ''
  try {
    const [summaryResp, geoResp] = await Promise.all([
      getSecuritySummary(),
      getSecurityGeoRisk(),
    ])
    summary.value = {
      ...summary.value,
      ...summaryResp.data.data,
    }
    geoRiskItems.value = geoResp.data.data.items || []
  } catch (error) {
    errorMessage.value = error.message
  } finally {
    loading.value = false
  }
}

// 挂载时先读一次本地缓存的流量配置做即时预览，再订阅配置变更事件，
// 使系统配置页保存后总览页的“流量开关/模式”能实时联动；onUnmounted 取消订阅避免内存泄漏
onMounted(() => {
  const recentFlowConfig = readSecurityFlowConfigSync()
  applyFlowConfigPreview(recentFlowConfig)

  unsubscribeFlowConfigSync = subscribeSecurityFlowConfigSync((payload) => {
    applyFlowConfigPreview(payload)
  })

  loadSummary().then(() => {
    const latestFlowConfig = readSecurityFlowConfigSync()
    if (latestFlowConfig && Date.now() - latestFlowConfig.updatedAt <= 5 * 60 * 1000) {
      applyFlowConfigPreview(latestFlowConfig)
    }
  })
})

onUnmounted(() => {
  unsubscribeFlowConfigSync()
})
</script>

<style scoped>
.stat-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 16px;
  margin-bottom: 24px;
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
  font-size: 30px;
  color: var(--sa-color-primary-deep);
}

.quick-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
  gap: 16px;
  margin-bottom: 24px;
}

.quick-card {
  cursor: pointer;
  transition: transform 0.2s ease, box-shadow 0.2s ease;
}

.quick-card:hover {
  transform: translateY(-2px);
  box-shadow: 0 12px 28px var(--sa-color-shadow);
}

.quick-card h3 {
  margin: 0 0 10px;
  color: var(--sa-color-primary);
}

.quick-card p {
  margin: 0;
  color: var(--sa-color-text-secondary);
  line-height: 1.7;
}

.summary-card {
  margin-top: 24px;
}

.summary-line {
  margin: 0 0 8px;
  color: #41566b;
}

.summary-note {
  margin: 0;
  color: var(--sa-color-text-secondary);
  font-size: 13px;
}

.flow-trend-note {
  margin-bottom: 12px;
}

.source-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 16px;
  margin-top: 16px;
}

.source-group h4 {
  margin: 0 0 8px;
  color: var(--sa-color-primary);
}

.source-list {
  margin: 0;
  padding: 0;
  list-style: none;
  display: grid;
  gap: 6px;
}

.source-list li {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 8px 10px;
  border-radius: 8px;
  background: #f7f8fa;
  color: #41566b;
}

.flow-mode-list {
  margin-top: 12px;
}

.flow-trend-state {
  display: flex;
  gap: 6px;
  flex-wrap: wrap;
}

.chart-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
  gap: 16px;
  margin-top: 24px;
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

.geo-map-card {
  margin-top: 24px;
}

.geo-map-wrapper {
  height: 560px;
}
</style>
