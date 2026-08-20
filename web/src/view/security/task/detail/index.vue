<template>
  <section class="sa-page">
    <SecurityBreadcrumb />

    <header class="sa-page-header">
      <div>
        <h1>{{ content.title }}</h1>
        <p>{{ content.description }}</p>
      </div>
      <el-button plain @click="goBack">{{ content.backButton }}</el-button>
    </header>

    <el-alert
      v-if="errorMessage"
      class="sa-panel"
      type="error"
      :closable="false"
      :title="errorMessage"
    />

    <div v-else v-loading="loading" class="detail-grid">
      <el-card class="sa-panel" shadow="never">
        <template #header>{{ content.sections.basic }}</template>
        <el-descriptions v-if="taskDetail" :column="1" border>
          <el-descriptions-item label="任务编号">{{ taskDetail.taskId }}</el-descriptions-item>
          <el-descriptions-item label="任务单号">{{ taskDetail.taskNo }}</el-descriptions-item>
          <el-descriptions-item label="输入类型">{{ taskDetail.inputType === 'DOMAIN' ? '域名' : 'IP' }}</el-descriptions-item>
          <el-descriptions-item label="原始输入">{{ taskDetail.inputValue || taskDetail.targetIp }}</el-descriptions-item>
          <el-descriptions-item label="目标 IP">{{ taskDetail.targetIp }}</el-descriptions-item>
          <el-descriptions-item label="任务状态">
            <el-tag :type="getTaskStatusTag(taskDetail.taskStatus)">{{ getTaskStatusText(taskDetail.taskStatus) }}</el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="综合评分">{{ formatValue(taskDetail.scoreValue) }}</el-descriptions-item>
          <el-descriptions-item label="风险等级">
            <template v-if="taskDetail.riskLevel">
              <el-tag :type="getRiskLevelTag(taskDetail.riskLevel)">{{ getRiskLevelText(taskDetail.riskLevel) }}</el-tag>
            </template>
            <template v-else>-</template>
          </el-descriptions-item>
          <el-descriptions-item label="是否触发预警">{{ taskDetail.alertCreated ? '是' : '否' }}</el-descriptions-item>
          <el-descriptions-item v-if="taskDetail.errorMessage" :label="content.labels.errorMessage">
            {{ taskDetail.errorMessage }}
          </el-descriptions-item>
          <el-descriptions-item label="创建人">{{ taskDetail.createdBy }}</el-descriptions-item>
          <el-descriptions-item label="开始时间">{{ taskDetail.startedAt || '-' }}</el-descriptions-item>
          <el-descriptions-item label="结束时间">{{ taskDetail.finishedAt || '-' }}</el-descriptions-item>
          <el-descriptions-item label="创建时间">{{ taskDetail.createdAt }}</el-descriptions-item>
        </el-descriptions>
      </el-card>

      <el-card class="sa-panel" shadow="never">
        <template #header>{{ content.sections.baseInfo }}</template>
        <el-descriptions v-if="taskDetail?.baseInfo" :column="1" border>
          <el-descriptions-item label="国家">{{ formatBaseInfoValue(taskDetail.baseInfo.country) }}</el-descriptions-item>
          <el-descriptions-item label="地区">{{ formatBaseInfoValue(taskDetail.baseInfo.region, '库未提供') }}</el-descriptions-item>
          <el-descriptions-item label="城市">{{ formatBaseInfoValue(taskDetail.baseInfo.city, '库未提供') }}</el-descriptions-item>
          <el-descriptions-item label="运营商">{{ formatBaseInfoValue(taskDetail.baseInfo.isp, '库未提供') }}</el-descriptions-item>
          <el-descriptions-item label="经纬度">{{ formatCoordinate(taskDetail.baseInfo.latitude, taskDetail.baseInfo.longitude) }}</el-descriptions-item>
          <el-descriptions-item label="时区">{{ formatBaseInfoValue(taskDetail.baseInfo.timeZone, '库未提供') }}</el-descriptions-item>
          <el-descriptions-item label="精度半径">{{ formatAccuracyRadius(taskDetail.baseInfo.accuracyRadius) }}</el-descriptions-item>
          <el-descriptions-item label="WHOIS 组织">{{ formatBaseInfoValue(taskDetail.baseInfo.whoisOrg, 'RDAP 未返回') }}</el-descriptions-item>
          <el-descriptions-item label="WHOIS 联系方式">{{ formatBaseInfoValue(taskDetail.baseInfo.whoisContact, 'RDAP 未返回') }}</el-descriptions-item>
          <el-descriptions-item label="基础属性来源">{{ formatBaseInfoValue(taskDetail.baseInfo.sourceSummary) }}</el-descriptions-item>
          <el-descriptions-item label="基础属性原始证据">
            <pre class="json-block">{{ formatJson(taskDetail.baseInfo.rawPayload) }}</pre>
          </el-descriptions-item>
        </el-descriptions>
        <el-empty v-else :description="content.empty.baseInfo" />
      </el-card>

      <el-card class="sa-panel" shadow="never">
        <template #header>{{ content.sections.score }}</template>
        <el-descriptions v-if="taskDetail?.features || taskDetail?.score" :column="1" border>
          <el-descriptions-item label="信誉评分">{{ formatValue(taskDetail?.features?.reputationScore) }}</el-descriptions-item>
          <el-descriptions-item label="开放端口数">{{ formatValue(taskDetail?.features?.openPortCount) }}</el-descriptions-item>
          <el-descriptions-item label="高危端口数">{{ formatValue(taskDetail?.features?.highRiskPortCount) }}</el-descriptions-item>
          <el-descriptions-item label="地理风险标记">{{ formatBoolean(taskDetail?.features?.geoRiskFlag) }}</el-descriptions-item>
          <el-descriptions-item label="默认主链路来源">
            <div v-if="taskDetail?.features?.sourceChainGroups?.length" class="source-group-list">
              <div v-for="group in taskDetail.features.sourceChainGroups" :key="group.key" class="factor-item">
                <div class="factor-title">{{ group.label }}</div>
                <div class="factor-basis">{{ group.summary || '-' }}</div>
              </div>
            </div>
            <span v-else>{{ taskDetail?.features?.sourceSummary || '-' }}</span>
          </el-descriptions-item>
          <el-descriptions-item label="流量增强状态">{{ taskDetail?.features?.flowCapabilityText || '-' }}</el-descriptions-item>
          <el-descriptions-item v-if="taskDetail?.features?.flowSourceSummary" label="流量原型来源">
            {{ taskDetail.features.flowSourceSummary }}
          </el-descriptions-item>
          <el-descriptions-item v-if="taskDetail?.features?.flowSummary" label="流量原型摘要">{{ taskDetail.features.flowSummary }}</el-descriptions-item>
          <el-descriptions-item label="流量增强边界说明">{{ taskDetail?.features?.flowBoundaryText || '-' }}</el-descriptions-item>
          <el-descriptions-item label="特征摘要">{{ taskDetail?.features?.featureDigest || '-' }}</el-descriptions-item>
          <el-descriptions-item label="归一化特征">
            <pre class="json-block">{{ formatJson(taskDetail?.features?.normalizedFeatures) }}</pre>
          </el-descriptions-item>
          <el-descriptions-item label="证据链">
            <div v-if="defaultEvidenceItems.length" class="evidence-list">
              <div v-for="(item, index) in defaultEvidenceItems" :key="`${item.source}-${index}`" class="evidence-item">
                <div class="evidence-title">{{ item.title }} <span class="evidence-meta">[{{ item.categoryLabel || '其他证据' }} / {{ item.source }} / {{ item.riskHint || 'INFO' }}]</span></div>
                <div class="evidence-summary">{{ item.summary }}</div>
              </div>
            </div>
            <span v-else>-</span>
          </el-descriptions-item>
          <el-descriptions-item label="评分因子">
            <div v-if="taskDetail?.features?.scoreFactors?.length" class="factor-list">
              <div v-for="factor in taskDetail.features.scoreFactors" :key="factor.key" class="factor-item">
                <div class="factor-title">{{ factor.label }}: 原始分 {{ formatValue(factor.rawScore) }} × 权重 {{ formatValue(factor.weight) }} = {{ formatValue(factor.contribution) }}</div>
                <div class="factor-basis">来源依据：{{ factor.displayBasis || '-' }}</div>
              </div>
            </div>
            <span v-else>-</span>
          </el-descriptions-item>
          <el-descriptions-item label="综合评分">{{ formatValue(taskDetail?.score?.scoreValue) }}</el-descriptions-item>
          <el-descriptions-item label="风险等级">
            <template v-if="taskDetail?.score?.riskLevel">
              <el-tag :type="getRiskLevelTag(taskDetail.score.riskLevel)">{{ getRiskLevelText(taskDetail.score.riskLevel) }}</el-tag>
            </template>
            <template v-else>-</template>
          </el-descriptions-item>
          <el-descriptions-item label="评分原因">{{ taskDetail?.score?.scoreReason || '-' }}</el-descriptions-item>
          <el-descriptions-item label="规则修正">{{ taskDetail?.score?.ruleAdjustment || '-' }}</el-descriptions-item>
          <el-descriptions-item label="是否触发预警">{{ formatBoolean(taskDetail?.score?.isAlertTriggered) }}</el-descriptions-item>
        </el-descriptions>
        <el-empty v-else :description="content.empty.score" />
      </el-card>

      <el-card class="sa-panel" shadow="never">
        <template #header>{{ content.sections.flow }}</template>
        <el-descriptions v-if="taskDetail?.flow" :column="1" border>
          <el-descriptions-item label="流量模式">{{ taskDetail.flow.collectionMode || '-' }}</el-descriptions-item>
          <el-descriptions-item label="流量状态">{{ taskDetail.flow.collectionStatus || '-' }}</el-descriptions-item>
          <el-descriptions-item label="展示定位">
            <el-tag :type="hasRealFlowMetrics ? 'success' : 'warning'">
              {{ hasRealFlowMetrics ? '真实流量承接结果' : '原型入口 / 状态承接' }}
            </el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="解析器">{{ taskDetail.flow.parserName || '-' }}</el-descriptions-item>
          <el-descriptions-item label="解析器就绪">{{ formatBoolean(taskDetail.flow.parserReady) }}</el-descriptions-item>
          <el-descriptions-item label="流量来源链">{{ formatChain(taskDetail.flow.sourceChain) }}</el-descriptions-item>
          <el-descriptions-item label="摘要">{{ taskDetail.flow.summary || '-' }}</el-descriptions-item>
          <el-descriptions-item :label="content.flowLabels.realMetrics">
            <div v-if="realFlowStats.length" class="factor-list">
              <div v-for="fact in realFlowStats" :key="fact.label" class="factor-item">
                <div class="factor-title">{{ fact.label }}</div>
                <div class="factor-basis">{{ fact.value }}</div>
              </div>
            </div>
            <span v-else>当前主要承接原型入口状态，尚无稳定真实解析指标可展示。</span>
          </el-descriptions-item>
          <el-descriptions-item :label="content.flowLabels.signals">
            <div v-if="realFlowSignals.length" class="factor-list">
              <div v-for="fact in realFlowSignals" :key="fact.label" class="factor-item">
                <div class="factor-title">{{ fact.label }}</div>
                <div class="factor-basis">{{ fact.value }}</div>
              </div>
            </div>
            <span v-else>-</span>
          </el-descriptions-item>
          <el-descriptions-item :label="content.flowLabels.runtimeContext">
            <div v-if="runtimeContextFacts.length" class="factor-list">
              <div v-for="fact in runtimeContextFacts" :key="fact.label" class="factor-item">
                <div class="factor-title">{{ fact.label }}</div>
                <div class="factor-basis">{{ fact.value }}</div>
              </div>
            </div>
            <span v-else>-</span>
          </el-descriptions-item>
          <el-descriptions-item :label="content.flowLabels.entryFields">
            <div v-if="entryStateFacts.length" class="factor-list">
              <div v-for="fact in entryStateFacts" :key="fact.label" class="factor-item">
                <div class="factor-title">{{ fact.label }}</div>
                <div class="factor-basis">{{ fact.value }}</div>
              </div>
            </div>
            <span v-else>-</span>
          </el-descriptions-item>
          <el-descriptions-item :label="content.flowLabels.traceability">
            <div class="flow-traceability">
              <el-tag size="small" :type="taskDetail.flow.isTraceable ? 'success' : 'info'" effect="plain">
                {{ taskDetail.flow.isTraceable ? '已落库，可继续查看趋势与证据' : '未形成独立流量落库，仅保留入口状态说明' }}
              </el-tag>
              <span v-if="taskDetail.flow.isTraceable" class="factor-basis">
                历史={{ taskDetail.flow.historySourceTable || '-' }} / 趋势={{ taskDetail.flow.trendSourceTable || '-' }} / 证据={{ taskDetail.flow.evidenceSourceTable || '-' }}
              </span>
            </div>
          </el-descriptions-item>
          <el-descriptions-item label="真实流量证据">
            <div v-if="flowEvidenceItems.length" class="evidence-list">
              <div v-for="(item, index) in flowEvidenceItems" :key="`flow-${item.source}-${index}`" class="evidence-item">
                <div class="evidence-title">{{ item.title }} <span class="evidence-meta">[{{ item.categoryLabel || '流量证据' }} / {{ item.source }} / {{ item.riskHint || 'INFO' }}]</span></div>
                <div class="evidence-summary">{{ item.summary }}</div>
              </div>
            </div>
            <span v-else>-</span>
          </el-descriptions-item>
          <el-descriptions-item v-if="taskDetail.flow.collectionHistory?.length" :label="content.flowLabels.collectionHistory">
            <div class="timeline-list">
              <div v-for="item in taskDetail.flow.collectionHistory" :key="`collection-${item.collectionId}`" class="factor-item">
                <div class="factor-title">
                  #{{ item.collectionId }} / {{ item.collectionMode || '-' }} / {{ item.collectionStatus || '-' }}
                </div>
                <div class="factor-basis">
                  {{ item.createdAt || '-' }} / 包={{ item.packetCount }} / 字节={{ formatByteCount(item.byteCount) }} / 会话={{ item.conversationCount }} / 窗口={{ item.windowCount }} / 行为分={{ formatValue(item.behaviorRiskScore) }}
                </div>
                <div class="factor-basis">
                  {{ item.summary || '-' }}
                </div>
                <div v-if="item.featureDigest" class="factor-basis">
                  digest={{ item.featureDigest }}
                </div>
              </div>
            </div>
          </el-descriptions-item>
          <el-descriptions-item v-if="taskDetail.flow.evidenceTimeline?.length" :label="content.flowLabels.evidenceTimeline">
            <div class="timeline-list">
              <div v-for="item in taskDetail.flow.evidenceTimeline" :key="`timeline-${item.windowNo}-${item.windowStart}`" class="factor-item">
                <div class="factor-title">窗口 {{ item.windowNo }} | {{ item.windowStart }} ~ {{ item.windowEnd }}</div>
                <div class="factor-basis">
                  包={{ item.packetCount }} / 字节={{ formatByteCount(item.byteCount) }} / 会话={{ item.conversationCount }} / DNS={{ item.dnsEventCount }} / HTTP={{ item.httpEventCount }} / TLS={{ item.tlsEventCount }}
                </div>
              </div>
            </div>
          </el-descriptions-item>
          <el-descriptions-item v-if="taskDetail.flow.trend?.length" :label="content.flowLabels.trend">
            <div class="timeline-list">
              <div v-for="item in taskDetail.flow.trend" :key="`trend-${item.windowNo}-${item.windowStart}`" class="factor-item">
                <div class="factor-title">窗口 {{ item.windowNo }}</div>
                <div class="factor-basis">
                  {{ item.windowStart }} ~ {{ item.windowEnd }} / 包={{ item.packetCount }} / 会话={{ item.conversationCount }} / 高危端口命中={{ item.highRiskPortHitCount }}
                </div>
              </div>
            </div>
          </el-descriptions-item>
          <el-descriptions-item v-if="hasFlowDebugPayload" :label="content.flowLabels.rawPayload">
            <el-collapse class="flow-debug-collapse">
              <el-collapse-item v-if="taskDetail.flow.inputSnapshot && Object.keys(taskDetail.flow.inputSnapshot).length" title="输入快照" name="inputSnapshot">
                <pre class="json-block">{{ formatJson(taskDetail.flow.inputSnapshot) }}</pre>
              </el-collapse-item>
              <el-collapse-item v-if="taskDetail.flow.parsedMetrics && Object.keys(taskDetail.flow.parsedMetrics).length" title="解析指标原始结构" name="parsedMetrics">
                <pre class="json-block">{{ formatJson(taskDetail.flow.parsedMetrics) }}</pre>
              </el-collapse-item>
              <el-collapse-item v-if="taskDetail.flow.mappingBoundary && Object.keys(taskDetail.flow.mappingBoundary).length" title="字段映射边界" name="mappingBoundary">
                <pre class="json-block">{{ formatJson(taskDetail.flow.mappingBoundary) }}</pre>
              </el-collapse-item>
              <el-collapse-item v-if="taskDetail.flow.evidenceSnapshot && Object.keys(taskDetail.flow.evidenceSnapshot).length" title="证据快照" name="evidenceSnapshot">
                <pre class="json-block">{{ formatJson(taskDetail.flow.evidenceSnapshot) }}</pre>
              </el-collapse-item>
            </el-collapse>
          </el-descriptions-item>
        </el-descriptions>
        <el-empty v-else :description="content.empty.flow" />
      </el-card>

      <el-card class="sa-panel" shadow="never">
        <template #header>关联证据展示</template>
        <div v-if="evidenceGroups.length" class="evidence-groups">
          <div v-for="group in evidenceGroups" :key="group.key" class="evidence-group">
            <h4>{{ group.title }}</h4>
            <div class="evidence-list">
              <div v-for="(item, index) in group.items" :key="`${group.key}-${index}`" class="evidence-item">
                <div class="evidence-title">{{ item.title }} <span class="evidence-meta">[{{ item.categoryLabel || group.title }} / {{ item.source }} / {{ item.riskHint || 'INFO' }}]</span></div>
                <div class="evidence-summary">{{ item.summary }}</div>
              </div>
            </div>
          </div>
        </div>
        <el-empty v-else description="当前暂无可展示的关联证据" />
      </el-card>

      <el-card class="sa-panel" shadow="never">
        <template #header>IP-流量关联图谱</template>
        <SecurityRelationGraph :graph="relationGraph" />
        <el-descriptions class="sa-compact-desc" :column="2" border>
          <el-descriptions-item label="节点数">{{ relationGraph.nodes?.length || 0 }}</el-descriptions-item>
          <el-descriptions-item label="边数">{{ relationGraph.edges?.length || 0 }}</el-descriptions-item>
        </el-descriptions>
      </el-card>

      <el-card class="sa-panel" shadow="never">
        <template #header>{{ content.sections.alert }}</template>
        <el-descriptions v-if="taskDetail?.alert" :column="1" border>
          <el-descriptions-item label="预警编号">{{ taskDetail.alert.alertId }}</el-descriptions-item>
          <el-descriptions-item label="预警等级">
            <el-tag :type="getRiskLevelTag(taskDetail.alert.alertLevel)">{{ getRiskLevelText(taskDetail.alert.alertLevel) }}</el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="预警标题">{{ taskDetail.alert.alertTitle || '-' }}</el-descriptions-item>
          <el-descriptions-item label="预警内容">{{ taskDetail.alert.alertContent || '-' }}</el-descriptions-item>
          <el-descriptions-item label="通知渠道">{{ taskDetail.alert.channel || '-' }}</el-descriptions-item>
          <el-descriptions-item label="发送状态">
            <el-tag :type="getSendStatusTag(taskDetail.alert.sendStatus)">{{ getSendStatusText(taskDetail.alert.sendStatus) }}</el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="发送时间">{{ taskDetail.alert.sendTime || '-' }}</el-descriptions-item>
          <el-descriptions-item label="预警创建时间">{{ taskDetail.alert.createdAt || '-' }}</el-descriptions-item>
        </el-descriptions>
        <el-empty v-else :description="content.empty.alert" />
      </el-card>
    </div>
  </section>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import { getSecurityTaskDetail, getSecurityTaskRelationGraph } from '../../../../api/securityTask'
import SecurityBreadcrumb from '../../../../components/security/SecurityBreadcrumb.vue'
import SecurityRelationGraph from '../../../../components/security/SecurityRelationGraph.vue'
import {
  getRiskLevelTag,
  getRiskLevelText,
  getSendStatusTag,
  getSendStatusText,
  getTaskStatusTag,
  getTaskStatusText,
} from '../../../../constants/security'
import { securityPageContent } from '../../../../constants/securityContent'

const route = useRoute()
const router = useRouter()
const content = securityPageContent.taskDetail
const taskDetail = ref(null)
const relationGraph = ref({ nodes: [], edges: [] })
const loading = ref(false)
const errorMessage = ref('')

const taskId = computed(() => route.params.id)
const normalizedTaskId = computed(() => Number.parseInt(String(taskId.value), 10))

const formatValue = (value) => (value === 0 || value ? value : '-')
const formatBoolean = (value) => (typeof value === 'boolean' ? (value ? '是' : '否') : '-')
const formatChain = (items) => (Array.isArray(items) && items.length ? items.join(' -> ') : '-')
const formatWindow = (value) => (value ? `${value} 秒` : '-')
const formatByteCount = (value) => {
  if (value === 0) {
    return '0 B'
  }
  if (!value) {
    return '-'
  }
  if (value >= 1024 * 1024) {
    return `${(value / (1024 * 1024)).toFixed(2)} MB`
  }
  if (value >= 1024) {
    return `${(value / 1024).toFixed(2)} KB`
  }
  return `${value} B`
}
const formatBaseInfoValue = (value, fallback = '未获取') => {
  if (value === 0) {
    return '0'
  }
  if (!value) {
    return fallback
  }
  const text = String(value).trim()
  if (!text || text === '-') {
    return fallback
  }
  if (text.toUpperCase() === 'UNKNOWN') {
    return fallback
  }
  return text
}
const formatCoordinate = (latitude, longitude) => {
  const lat = Number(latitude)
  const lng = Number(longitude)
  if (!Number.isFinite(lat) || !Number.isFinite(lng)) {
    return '库未提供'
  }
  if (lat === 0 && lng === 0) {
    return '库未提供'
  }
  return `${lat.toFixed(3)}, ${lng.toFixed(3)}`
}
const formatAccuracyRadius = (value) => {
  const radius = Number(value)
  if (!Number.isFinite(radius) || radius <= 0) {
    return '库未提供'
  }
  return `${radius} km`
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
const defaultEvidenceItems = computed(() => {
  return Array.isArray(taskDetail.value?.features?.evidenceItems) ? taskDetail.value.features.evidenceItems : []
})
const prototypeFlowEvidence = computed(() => {
  return Array.isArray(taskDetail.value?.features?.flowPrototypeItems) ? taskDetail.value.features.flowPrototypeItems : []
})
const flowEvidenceItems = computed(() => {
  if (Array.isArray(taskDetail.value?.flow?.evidenceItems) && taskDetail.value.flow.evidenceItems.length) {
    return taskDetail.value.flow.evidenceItems
  }
  return prototypeFlowEvidence.value
})
const evidenceGroups = computed(() => {
  return Array.isArray(taskDetail.value?.features?.evidenceGroups) ? taskDetail.value.features.evidenceGroups : []
})
const hasFlowDebugPayload = computed(() => {
  const flow = taskDetail.value?.flow
  if (!flow) {
    return false
  }
  return [
    flow.inputSnapshot,
    flow.parsedMetrics,
    flow.mappingBoundary,
    flow.evidenceSnapshot,
  ].some((item) => item && typeof item === 'object' && Object.keys(item).length)
})
const hasRealFlowMetrics = computed(() => {
  const flow = taskDetail.value?.flow
  if (!flow) {
    return false
  }
  if (flow.packetCount > 0 || flow.byteCount > 0 || flow.conversationCount > 0 || flow.windowCount > 0) {
    return true
  }
  return Boolean(flow.parsedMetrics && Object.keys(flow.parsedMetrics).length)
})
const realFlowStats = computed(() => {
  const flow = taskDetail.value?.flow
  if (!flow) {
    return []
  }
  const hasStableMetric = flow.packetCount > 0 || flow.byteCount > 0 || flow.conversationCount > 0 || flow.windowCount > 0
  const items = []
  if (flow.packetCount > 0) {
    items.push({ label: '数据包数', value: formatValue(flow.packetCount) })
  }
  if (flow.byteCount > 0) {
    items.push({ label: '字节数', value: formatByteCount(flow.byteCount) })
  }
  if (flow.conversationCount > 0) {
    items.push({ label: '会话数', value: formatValue(flow.conversationCount) })
  }
  if (flow.windowCount > 0) {
    items.push({ label: '窗口数', value: formatValue(flow.windowCount) })
  }
  if (flow.windowSeconds > 0) {
    items.push({ label: '采集窗口', value: formatWindow(flow.windowSeconds) })
  }
  if (hasStableMetric && (flow.behaviorRiskScore === 0 || flow.behaviorRiskScore)) {
    items.push({ label: '行为风险分', value: formatValue(flow.behaviorRiskScore) })
  }
  if (flow.peakPps > 0) {
    items.push({ label: '峰值 PPS', value: formatValue(flow.peakPps) })
  }
  if (flow.burstScore > 0) {
    items.push({ label: '突发评分', value: formatValue(flow.burstScore) })
  }
  if (flow.scanScore > 0) {
    items.push({ label: '扫描评分', value: formatValue(flow.scanScore) })
  }
  return items
})

const realFlowSignals = computed(() => {
  const flow = taskDetail.value?.flow
  if (!flow) {
    return []
  }
  const parsedMetrics = flow.parsedMetrics || {}
  const items = []
  const formatTopCounts = (values) => {
    if (!Array.isArray(values) || !values.length) {
      return ''
    }
    return values
      .slice(0, 5)
      .map((item) => `${item.key || '-'}(${item.count ?? 0})`)
      .join(' / ')
  }
  if (parsedMetrics.dnsEventCount > 0 || parsedMetrics.httpEventCount > 0 || parsedMetrics.tlsEventCount > 0) {
    items.push({
      label: '协议事件',
      value: `DNS=${formatValue(parsedMetrics.dnsEventCount)} / HTTP=${formatValue(parsedMetrics.httpEventCount)} / TLS=${formatValue(parsedMetrics.tlsEventCount)}`,
    })
  }
  const dnsTopQuestions = Array.isArray(flow.dnsTopQuestions) && flow.dnsTopQuestions.length
    ? flow.dnsTopQuestions
    : parsedMetrics.dnsTopQuestions
  if (Array.isArray(dnsTopQuestions) && dnsTopQuestions.length) {
    items.push({
      label: 'DNS 目标域名',
      value: formatTopCounts(dnsTopQuestions),
    })
  }
  const dnsQueryTypeHints = Array.isArray(flow.dnsQueryTypeHints) && flow.dnsQueryTypeHints.length
    ? flow.dnsQueryTypeHints
    : parsedMetrics.dnsQueryTypeHints
  if (Array.isArray(dnsQueryTypeHints) && dnsQueryTypeHints.length) {
    items.push({
      label: 'DNS 查询类型',
      value: formatTopCounts(dnsQueryTypeHints),
    })
  }
  const applicationSignals = Array.isArray(flow.applicationSignals) && flow.applicationSignals.length
    ? flow.applicationSignals
    : parsedMetrics.applicationSignals
  if (Array.isArray(applicationSignals) && applicationSignals.length) {
    items.push({
      label: '应用层动态信号',
      value: applicationSignals.join(' | '),
    })
  }
  const httpHostHints = Array.isArray(flow.httpHostHints) && flow.httpHostHints.length
    ? flow.httpHostHints
    : parsedMetrics.httpHostHints
  if (Array.isArray(httpHostHints) && httpHostHints.length) {
    items.push({
      label: 'HTTP Host 提示',
      value: formatTopCounts(httpHostHints),
    })
  }
  const httpMethodHints = Array.isArray(flow.httpMethodHints) && flow.httpMethodHints.length
    ? flow.httpMethodHints
    : parsedMetrics.httpMethodHints
  if (Array.isArray(httpMethodHints) && httpMethodHints.length) {
    items.push({
      label: 'HTTP 方法提示',
      value: httpMethodHints
        .slice(0, 5)
        .map((item) => `${item.method || '-'}(${item.count ?? 0})`)
        .join(' / '),
    })
  }
  const httpStatusHints = Array.isArray(flow.httpStatusHints) && flow.httpStatusHints.length
    ? flow.httpStatusHints
    : parsedMetrics.httpStatusHints
  if (Array.isArray(httpStatusHints) && httpStatusHints.length) {
    items.push({
      label: 'HTTP 状态码',
      value: formatTopCounts(httpStatusHints),
    })
  }
  const tlsHandshakeHints = Array.isArray(flow.tlsHandshakeHints) && flow.tlsHandshakeHints.length
    ? flow.tlsHandshakeHints
    : parsedMetrics.tlsHandshakeHints
  if (Array.isArray(tlsHandshakeHints) && tlsHandshakeHints.length) {
    items.push({
      label: 'TLS 握手提示',
      value: tlsHandshakeHints
        .slice(0, 5)
        .map((item) => `${item.serverName || '-'}(${item.count ?? 0})`)
        .join(' / '),
    })
  }
  const tlsVersionHints = Array.isArray(flow.tlsVersionHints) && flow.tlsVersionHints.length
    ? flow.tlsVersionHints
    : parsedMetrics.tlsVersionHints
  if (Array.isArray(tlsVersionHints) && tlsVersionHints.length) {
    items.push({
      label: 'TLS 版本',
      value: formatTopCounts(tlsVersionHints),
    })
  }
  const directionalityIndicators = flow.directionalityIndicators || parsedMetrics.directionalityIndicators
  if (directionalityIndicators && typeof directionalityIndicators === 'object') {
    items.push({
      label: '方向性侧写',
      value: `主方向=${directionalityIndicators.dominantDirection || '-'} / 入包=${formatValue(directionalityIndicators.inboundPacketCount)} / 出包=${formatValue(directionalityIndicators.outboundPacketCount)} / bias=${formatValue(directionalityIndicators.packetBias)}`,
    })
  }
  const portDensityIndicators = flow.portDensityIndicators || parsedMetrics.portDensityIndicators
  if (portDensityIndicators && typeof portDensityIndicators === 'object') {
    items.push({
      label: '端口密度',
      value: `目标端口=${formatValue(portDensityIndicators.uniqueTargetPortCount)} / 高危端口=${formatValue(portDensityIndicators.highRiskTargetPortCount)} / 密度=${formatValue(portDensityIndicators.targetPortDensity)}`,
    })
  }
  const payloadEntropyIndicators = flow.payloadEntropyIndicators || parsedMetrics.payloadEntropyIndicators
  if (payloadEntropyIndicators && typeof payloadEntropyIndicators === 'object') {
    items.push({
      label: '载荷熵信号',
      value: `高熵报文=${formatValue(payloadEntropyIndicators.highEntropyPacketCount)} / 平均熵=${formatValue(payloadEntropyIndicators.averagePayloadEntropy)}`,
    })
  }
  if (flow.protocolDistribution && Object.keys(flow.protocolDistribution).length) {
    items.push({
      label: '协议分布',
      value: Object.entries(flow.protocolDistribution)
        .map(([protocol, count]) => `${protocol}=${count}`)
        .join(' / '),
    })
  }
  if (Array.isArray(flow.topPorts) && flow.topPorts.length) {
    items.push({
      label: '高频端口',
      value: flow.topPorts
        .slice(0, 5)
        .map((item) => {
          const port = item.port ?? item.value ?? '-'
          const count = item.count ?? item.hitCount ?? item.packetCount ?? '-'
          return `${port}(${count})`
        })
        .join(' / '),
    })
  }
  if (Array.isArray(flow.peerEndpoints) && flow.peerEndpoints.length) {
    items.push({
      label: '对端端点',
      value: flow.peerEndpoints
        .slice(0, 5)
        .map((item) => item.endpoint || item.ip || item.address || JSON.stringify(item))
        .join(' / '),
    })
  }
  if (flow.featureDigest) {
    items.push({
      label: '流量摘要指纹',
      value: flow.featureDigest,
    })
  }
  return items
})
const runtimeContextFacts = computed(() => {
  const flow = taskDetail.value?.flow
  if (!flow) {
    return []
  }
  const items = []
  if (flow.sampleProfile) {
    items.push({ label: '样本配置', value: flow.sampleProfile })
  }
  if (flow.interfaceName) {
    items.push({ label: '抓包网卡', value: flow.interfaceName })
  }
  if (flow.pcapFilePath) {
    items.push({ label: 'PCAP 路径', value: flow.pcapFilePath })
  }
  if (flow.startedAt) {
    items.push({ label: '开始时间', value: flow.startedAt })
  }
  if (flow.finishedAt) {
    items.push({ label: '结束时间', value: flow.finishedAt })
  }
  if (flow.createdAt) {
    items.push({ label: '记录创建时间', value: flow.createdAt })
  }
  return items
})
const entryStateFacts = computed(() => {
  const flow = taskDetail.value?.flow
  if (!flow) {
    return []
  }
  const items = []
  if (flow.collectionMode) {
    items.push({ label: '模式', value: flow.collectionMode })
  }
  if (flow.collectionStatus) {
    items.push({ label: '状态', value: flow.collectionStatus })
  }
  if (flow.parserName) {
    items.push({ label: '解析器', value: flow.parserName })
  }
  items.push({ label: '解析器就绪', value: formatBoolean(flow.parserReady) })
  if (flow.integrationStage) {
    items.push({ label: '接入阶段', value: flow.integrationStage })
  }
  if (flow.inputKind) {
    items.push({ label: '输入类型', value: flow.inputKind })
  }
  if (flow.prototypeBoundary) {
    items.push({ label: '边界语义', value: flow.prototypeBoundary })
  }
  return items
})

const loadTaskDetail = async () => {
  if (!Number.isInteger(normalizedTaskId.value) || normalizedTaskId.value <= 0) {
    errorMessage.value = content.notFound
    taskDetail.value = null
    relationGraph.value = { nodes: [], edges: [] }
    return
  }

  loading.value = true
  errorMessage.value = ''
  try {
    const [detailResp, relationResp] = await Promise.all([
      getSecurityTaskDetail(normalizedTaskId.value),
      getSecurityTaskRelationGraph(normalizedTaskId.value),
    ])
    taskDetail.value = detailResp.data.data
    relationGraph.value = relationResp.data.data || { nodes: [], edges: [] }
  } catch (error) {
    errorMessage.value = error.message === '任务不存在或已删除' ? content.notFound : error.message
  } finally {
    loading.value = false
  }
}

const goBack = () => {
  router.push('/security/task')
}

onMounted(loadTaskDetail)
</script>

<style scoped>
.detail-grid {
  display: grid;
  gap: 16px;
}

.json-block {
  margin: 0;
  white-space: pre-wrap;
  word-break: break-all;
  font-size: 12px;
  line-height: 1.5;
}

.evidence-list,
.factor-list,
.source-group-list,
.timeline-list {
  display: grid;
  gap: 8px;
}

.evidence-groups {
  display: grid;
  gap: 16px;
}

.evidence-group h4 {
  margin: 0 0 10px;
  color: #12344d;
}

.evidence-item,
.factor-item {
  padding: 8px 10px;
  border-radius: 8px;
  background: #f7f8fa;
}

.evidence-title,
.factor-title {
  font-weight: 600;
  color: #1f2329;
}

.evidence-meta,
.factor-basis,
.evidence-summary {
  font-size: 12px;
  color: #4e5969;
}

.flow-traceability {
  display: grid;
  gap: 8px;
}

.flow-debug-collapse {
  width: 100%;
}

.sa-compact-desc {
  margin-top: 12px;
}
</style>
