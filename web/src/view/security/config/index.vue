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
      <el-alert
        v-if="!userStore.canEditConfig"
        class="sa-table-alert"
        type="info"
        :closable="false"
        :title="content.readonlyHint"
      />

      <el-alert
        v-if="errorMessage"
        class="sa-table-alert"
        type="error"
        :closable="false"
        :title="errorMessage"
      />

      <el-form v-loading="loading" :model="form" label-width="140px">
        <h3 class="section-title">{{ content.sourceTitle }}</h3>
        <p class="source-select-hint">{{ content.sourceSelectHint }}</p>

        <el-form-item :label="content.fields.whoisEndpoint">
          <el-select
            v-model="selectedWhoisSources"
            class="source-select"
            multiple
            clearable
            :disabled="!userStore.canEditConfig"
            placeholder="请选择 WHOIS 数据源"
            @change="handleSourceChange('whois')"
          >
            <el-option
              v-for="item in whoisSourceCards"
              :key="item.value"
              :label="item.label"
              :value="item.value"
            />
          </el-select>
        </el-form-item>

        <el-form-item :label="content.fields.reputationEndpoint">
          <el-select
            v-model="selectedReputationSources"
            class="source-select"
            multiple
            clearable
            :disabled="!userStore.canEditConfig"
            placeholder="请选择信誉数据源"
            @change="handleSourceChange('reputation')"
          >
            <el-option
              v-for="item in reputationSourceCards"
              :key="item.value"
              :label="item.label"
              :value="item.value"
            />
          </el-select>
        </el-form-item>

        <el-form-item :label="content.fields.attackSurfaceEndpoint">
          <el-select
            v-model="selectedAttackSurfaceSources"
            class="source-select"
            multiple
            clearable
            :disabled="!userStore.canEditConfig"
            placeholder="请选择攻击面数据源"
            @change="handleSourceChange('attackSurface')"
          >
            <el-option
              v-for="item in attackSurfaceSourceCards"
              :key="item.value"
              :label="item.label"
              :value="item.value"
            />
          </el-select>
        </el-form-item>

        <el-form-item :label="content.fields.flowEnabled">
          <el-switch v-model="form.flowEnabled" :disabled="!userStore.canEditConfig" />
        </el-form-item>
        <el-form-item :label="content.fields.flowMode">
          <el-select v-model="form.flowMode" :disabled="!userStore.canEditConfig || !form.flowEnabled">
            <el-option v-for="item in flowModeOptions" :key="item.value" :label="item.label" :value="item.value" />
          </el-select>
        </el-form-item>
        <el-form-item v-if="form.flowMode === 'online_capture'" :label="content.fields.flowInterfaceName">
          <el-select
            v-model="form.flowInterfaceName"
            filterable
            clearable
            :disabled="!userStore.canEditConfig || !form.flowEnabled"
            placeholder="请选择在线抓包网卡"
          >
            <el-option
              v-for="item in flowInterfaceOptions"
              :key="item.name"
              :label="buildFlowInterfaceLabel(item)"
              :value="item.name"
            />
          </el-select>
        </el-form-item>
        <el-form-item v-if="form.flowMode === 'offline_pcap'" :label="content.fields.flowPcapFilePath">
          <el-input v-model="form.flowPcapFilePath" :disabled="!userStore.canEditConfig || !form.flowEnabled" placeholder="例如：F:/captures/demo.pcapng" />
        </el-form-item>
        <el-form-item v-if="form.flowMode === 'sample'" :label="content.fields.flowSampleProfile">
          <el-input v-model="form.flowSampleProfile" :disabled="!userStore.canEditConfig || !form.flowEnabled" placeholder="例如：baseline-web" />
        </el-form-item>
        <el-form-item :label="content.fields.flowWindowSeconds">
          <el-input-number v-model="form.flowWindowSeconds" :disabled="!userStore.canEditConfig || !form.flowEnabled" :min="1" :step="1" />
        </el-form-item>
        <el-form-item :label="content.fields.flowTimeoutSeconds">
          <el-input-number v-model="form.flowTimeoutSeconds" :disabled="!userStore.canEditConfig || !form.flowEnabled" :min="1" :step="1" />
        </el-form-item>
        <el-form-item :label="content.fields.notifyChannel">
          <el-input v-model="form.notifyChannel" :disabled="!userStore.canEditConfig" />
        </el-form-item>
        <el-form-item label="邮件预警开关">
          <el-switch v-model="form.mailEnabled" :disabled="!userStore.canEditConfig" />
        </el-form-item>
        <el-form-item label="SMTP 主机">
          <el-input v-model="form.smtpHost" :disabled="!userStore.canEditConfig || !form.mailEnabled" />
        </el-form-item>
        <el-form-item label="SMTP 端口">
          <el-input-number v-model="form.smtpPort" :disabled="!userStore.canEditConfig || !form.mailEnabled" :min="1" :step="1" />
        </el-form-item>
        <el-form-item label="SMTP 用户名">
          <el-input v-model="form.smtpUsername" :disabled="!userStore.canEditConfig || !form.mailEnabled" />
        </el-form-item>
        <el-form-item label="SMTP 密码">
          <el-input v-model="form.smtpPassword" show-password :disabled="!userStore.canEditConfig || !form.mailEnabled" />
        </el-form-item>
        <el-form-item label="发件人">
          <el-input v-model="form.mailSender" :disabled="!userStore.canEditConfig || !form.mailEnabled" />
        </el-form-item>
        <el-form-item label="收件人">
          <el-input v-model="form.mailRecipient" :disabled="!userStore.canEditConfig || !form.mailEnabled" />
        </el-form-item>
        <el-form-item label="启用 TLS">
          <el-switch v-model="form.smtpUseTLS" :disabled="!userStore.canEditConfig || !form.mailEnabled" />
        </el-form-item>

        <h3 class="section-title">{{ content.thresholdTitle }}</h3>
        <el-form-item :label="content.fields.highRiskThreshold">
          <el-input-number v-model="form.highRiskThreshold" :disabled="!userStore.canEditConfig" :precision="2" :step="1" />
        </el-form-item>
        <el-form-item :label="content.fields.criticalRiskThreshold">
          <el-input-number v-model="form.criticalRiskThreshold" :disabled="!userStore.canEditConfig" :precision="2" :step="1" />
        </el-form-item>

        <h3 class="section-title">{{ content.weightTitle }}</h3>
        <el-form-item :label="content.fields.whoisWeight">
          <el-input-number v-model="form.weights.whoisWeight" :disabled="!userStore.canEditConfig" :precision="4" :step="0.0001" />
        </el-form-item>
        <el-form-item :label="content.fields.reputationWeight">
          <el-input-number v-model="form.weights.reputationWeight" :disabled="!userStore.canEditConfig" :precision="4" :step="0.0001" />
        </el-form-item>
        <el-form-item :label="content.fields.attackSurfaceWeight">
          <el-input-number v-model="form.weights.attackSurfaceWeight" :disabled="!userStore.canEditConfig" :precision="4" :step="0.0001" />
        </el-form-item>
        <el-form-item :label="content.fields.behaviorWeight">
          <el-input-number v-model="form.weights.behaviorWeight" :disabled="!userStore.canEditConfig" :precision="4" :step="0.0001" />
        </el-form-item>
        <el-form-item label="当前总分">
          <div class="weight-summary">
            <el-tag :type="isWeightSumValid ? 'success' : 'danger'">{{ weightSumText }}</el-tag>
            <span class="weight-note">{{ isWeightSumValid ? '总分满足 1.0000，可保存' : '总分必须严格等于 1.0000' }}</span>
          </div>
        </el-form-item>

        <el-form-item v-if="userStore.canEditConfig">
          <el-button type="primary" :loading="saving" :disabled="!isWeightSumValid" @click="handleSave">{{ content.saveButton }}</el-button>
        </el-form-item>
      </el-form>
    </el-card>
  </section>
</template>

<script setup>
import { computed, onMounted, reactive, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'

import { getFlowInterfaces, getSecurityConfig, updateSecurityConfig } from '../../../api/securityConfig'
import SecurityBreadcrumb from '../../../components/security/SecurityBreadcrumb.vue'
import { securityPageContent } from '../../../constants/securityContent'
import { emitSecurityFlowConfigSync } from '../../../hooks/useSecurityFlowConfigSync'
import { useUserStore } from '../../../pinia/modules/user'

const userStore = useUserStore()
const content = securityPageContent.config
const loading = ref(false)
const saving = ref(false)
const errorMessage = ref('')
const demoMode = ref(false)
const flowInterfaceOptions = ref([])
const selectedWhoisSources = ref([])
const selectedReputationSources = ref([])
const selectedAttackSurfaceSources = ref([])

const createDefaultForm = () => ({
  whoisEndpoint: 'geolite2+rdap',
  reputationEndpoint: 'local-blacklist',
  attackSurfaceEndpoint: 'limited-port-scan',
  flowEnabled: false,
  flowMode: 'sample',
  flowInterfaceName: '',
  flowPcapFilePath: '',
  flowSampleProfile: 'baseline-web',
  flowWindowSeconds: 60,
  flowTimeoutSeconds: 5,
  notifyChannel: '',
  mailEnabled: false,
  smtpHost: '',
  smtpPort: 25,
  smtpUsername: '',
  smtpPassword: '',
  mailSender: '',
  mailRecipient: '',
  smtpUseTLS: false,
  highRiskThreshold: 75,
  criticalRiskThreshold: 90,
  weights: {
    whoisWeight: 0.2,
    reputationWeight: 0.35,
    attackSurfaceWeight: 0.3,
    behaviorWeight: 0.15,
  },
})

const form = reactive(createDefaultForm())

const whoisSourceCards = computed(() => {
  const items = [
    { label: 'GeoLite2', value: 'geolite2' },
    { label: 'RDAP', value: 'rdap' },
  ]
  if (demoMode.value) {
    items.push({ label: 'local-demo', value: 'local-demo' })
  }
  return items
})

const reputationSourceCards = computed(() => {
  const items = [
    { label: 'local-blacklist', value: 'local-blacklist' },
    { label: 'abuseipdb', value: 'abuseipdb' },
  ]
  if (demoMode.value) {
    items.push({ label: 'local-demo', value: 'local-demo' })
  }
  return items
})

const attackSurfaceSourceCards = [
  { label: 'limited-port-scan', value: 'limited-port-scan' },
  { label: 'nmap-enhanced', value: 'nmap-enhanced' },
]

const flowModeOptions = [
  { label: '样本原型', value: 'sample' },
  { label: '离线 pcap', value: 'offline_pcap' },
  { label: '在线抓包', value: 'online_capture' },
]

const weightSumBasisPoint = computed(() => {
  return [
    form.weights.whoisWeight,
    form.weights.reputationWeight,
    form.weights.attackSurfaceWeight,
    form.weights.behaviorWeight,
  ].reduce((total, item) => total + Math.round(Number(item || 0) * 10000), 0)
})

const isWeightSumValid = computed(() => weightSumBasisPoint.value === 10000)
const weightSumText = computed(() => (weightSumBasisPoint.value / 10000).toFixed(4))

const unique = (items) => Array.from(new Set(items.filter(Boolean)))

const getSourceTarget = (groupKey) => {
  switch (groupKey) {
    case 'whois':
      return selectedWhoisSources
    case 'reputation':
      return selectedReputationSources
    case 'attackSurface':
      return selectedAttackSurfaceSources
    default:
      return selectedWhoisSources
  }
}

const decodeEndpointSelection = (value, cards) => {
  const trimmed = (value || '').trim().toLowerCase()
  if (!trimmed || trimmed === 'disabled') {
    return []
  }
  if (trimmed === 'local-demo') {
    return cards.some((item) => item.value === 'local-demo') ? ['local-demo'] : []
  }
  return unique(trimmed.split('+').filter((item) => cards.some((card) => card.value === item)))
}

const normalizeSelectedItems = (items) => {
  const normalized = unique(items)
  if (normalized.includes('local-demo')) {
    return ['local-demo']
  }
  return normalized.filter((item) => item !== 'local-demo')
}

const encodeEndpointSelection = (selectedItems, allCards) => {
  const items = unique(selectedItems)
  if (items.includes('local-demo')) {
    return 'local-demo'
  }
  const ordered = allCards.map((item) => item.value).filter((value) => items.includes(value) && value !== 'local-demo')
  if (!ordered.length) {
    return 'disabled'
  }
  return ordered.join('+')
}

const syncSourceSelectionsToForm = () => {
  form.whoisEndpoint = encodeEndpointSelection(selectedWhoisSources.value, whoisSourceCards.value)
  form.reputationEndpoint = encodeEndpointSelection(selectedReputationSources.value, reputationSourceCards.value)
  form.attackSurfaceEndpoint = encodeEndpointSelection(selectedAttackSurfaceSources.value, attackSurfaceSourceCards)
}

const applyConfig = (data) => {
  demoMode.value = Boolean(data.demoMode)
  selectedWhoisSources.value = decodeEndpointSelection(data.whoisEndpoint, whoisSourceCards.value)
  selectedReputationSources.value = decodeEndpointSelection(data.reputationEndpoint, reputationSourceCards.value)
  selectedAttackSurfaceSources.value = decodeEndpointSelection(data.attackSurfaceEndpoint || 'limited-port-scan', attackSurfaceSourceCards)
  syncSourceSelectionsToForm()
  form.flowEnabled = Boolean(data.flowEnabled)
  form.flowMode = data.flowMode || 'sample'
  form.flowInterfaceName = data.flowInterfaceName || ''
  form.flowPcapFilePath = data.flowPcapFilePath || ''
  form.flowSampleProfile = data.flowSampleProfile || 'baseline-web'
  form.flowWindowSeconds = Number(data.flowWindowSeconds || 60)
  form.flowTimeoutSeconds = Number(data.flowTimeoutSeconds || 5)
  form.notifyChannel = data.notifyChannel
  form.mailEnabled = Boolean(data.mailEnabled)
  form.smtpHost = data.smtpHost || ''
  form.smtpPort = Number(data.smtpPort || 25)
  form.smtpUsername = data.smtpUsername || ''
  form.smtpPassword = ''
  form.mailSender = data.mailSender || ''
  form.mailRecipient = data.mailRecipient || ''
  form.smtpUseTLS = Boolean(data.smtpUseTLS)
  form.highRiskThreshold = data.highRiskThreshold
  form.criticalRiskThreshold = data.criticalRiskThreshold
  form.weights.whoisWeight = data.weights.whoisWeight
  form.weights.reputationWeight = data.weights.reputationWeight
  form.weights.attackSurfaceWeight = data.weights.attackSurfaceWeight
  form.weights.behaviorWeight = data.weights.behaviorWeight
}

const handleSourceChange = (groupKey) => {
  const target = getSourceTarget(groupKey)
  target.value = normalizeSelectedItems(target.value)
}

const loadConfig = async () => {
  loading.value = true
  errorMessage.value = ''
  try {
    const resp = await getSecurityConfig()
    applyConfig(resp.data.data)
  } catch (error) {
    errorMessage.value = `${content.loadError}: ${error.message}`
  } finally {
    loading.value = false
  }
}

const loadFlowInterfaces = async () => {
  try {
    const resp = await getFlowInterfaces()
    flowInterfaceOptions.value = resp.data.data || []
  } catch {
    flowInterfaceOptions.value = []
  }
}

const buildFlowInterfaceLabel = (item) => {
  const parts = [item.name]
  if (item.interfaceDescription) {
    parts.push(item.interfaceDescription)
  }
  if (item.status) {
    parts.push(`状态=${item.status}`)
  }
  return parts.join(' / ')
}

watch(
  [selectedWhoisSources, selectedReputationSources, selectedAttackSurfaceSources],
  () => {
    syncSourceSelectionsToForm()
  },
  { deep: true },
)

watch(
  () => [form.flowEnabled, form.flowMode],
  ([flowEnabled, flowMode]) => {
    emitSecurityFlowConfigSync({ flowEnabled, flowMode })
  },
)

const handleSave = async () => {
  if (!isWeightSumValid.value) {
    ElMessage.error('评分权重总和必须严格等于 1.0000')
    return
  }
  saving.value = true
  errorMessage.value = ''
  try {
    const resp = await updateSecurityConfig({
      ...form,
      weights: { ...form.weights },
    })
    applyConfig(resp.data.data)
    emitSecurityFlowConfigSync(resp.data.data)
    ElMessage.success(content.saveSuccess)
  } catch (error) {
    errorMessage.value = error.message
    ElMessage.error(error.message)
  } finally {
    saving.value = false
  }
}

onMounted(async () => {
  await Promise.all([loadConfig(), loadFlowInterfaces()])
})
</script>

<style scoped>
.section-title {
  margin: 0 0 16px;
  color: var(--sa-color-primary);
}

.source-select-hint {
  margin: 0 0 16px;
  color: var(--sa-color-text-secondary);
  font-size: 13px;
}

.source-select {
  width: 100%;
}

.source-select :deep(.el-select__selection .el-tag) {
  background: #f0f9eb;
  border-color: #e1f3d8;
  color: #67c23a;
}

.source-select :deep(.el-select__selection .el-tag .el-tag__close) {
  color: #dc0400;
  border-color: #e1f3d8;
}

.source-select :deep(.el-select__selection .el-tag .el-tag__close:hover) {
  background: #ff2200;
  color: #fff;
}

.weight-summary {
  display: flex;
  align-items: center;
  gap: 12px;
  flex-wrap: wrap;
}

.weight-note {
  color: var(--sa-color-text-secondary);
  font-size: 13px;
}
</style>
