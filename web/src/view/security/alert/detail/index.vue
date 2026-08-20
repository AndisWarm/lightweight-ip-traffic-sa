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
        <el-descriptions v-if="alertDetail" :column="1" border>
          <el-descriptions-item label="预警编号">{{ alertDetail.alertId }}</el-descriptions-item>
          <el-descriptions-item label="预警等级">{{ getRiskLevelText(alertDetail.alertLevel) }}</el-descriptions-item>
          <el-descriptions-item label="预警标题">{{ alertDetail.alertTitle }}</el-descriptions-item>
          <el-descriptions-item label="预警内容">{{ alertDetail.alertContent }}</el-descriptions-item>
          <el-descriptions-item label="来源类型">{{ formatSourceType(alertDetail.sourceType) }}</el-descriptions-item>
          <el-descriptions-item label="来源标识">{{ alertDetail.sourceLabel || '-' }}</el-descriptions-item>
          <el-descriptions-item label="监控会话">{{ alertDetail.monitorSessionId || '-' }}</el-descriptions-item>
          <el-descriptions-item label="通知渠道">{{ alertDetail.channel }}</el-descriptions-item>
          <el-descriptions-item label="发送状态">{{ getSendStatusText(alertDetail.sendStatus) }}</el-descriptions-item>
          <el-descriptions-item label="发送时间">{{ alertDetail.sendTime || '-' }}</el-descriptions-item>
          <el-descriptions-item label="创建时间">{{ alertDetail.createdAt }}</el-descriptions-item>
        </el-descriptions>
      </el-card>

      <el-card class="sa-panel" shadow="never">
        <template #header>{{ content.sections.task }}</template>
        <el-descriptions v-if="alertDetail?.task" :column="1" border>
          <el-descriptions-item label="任务编号">{{ alertDetail.task.taskId }}</el-descriptions-item>
          <el-descriptions-item label="任务单号">{{ alertDetail.task.taskNo }}</el-descriptions-item>
          <el-descriptions-item label="目标 IP">{{ alertDetail.task.targetIp }}</el-descriptions-item>
          <el-descriptions-item label="任务状态">{{ getTaskStatusText(alertDetail.task.taskStatus) }}</el-descriptions-item>
        </el-descriptions>
        <el-empty v-else description="该预警来自实时监控，未绑定任务。" />
      </el-card>

      <el-card class="sa-panel" shadow="never">
        <template #header>{{ content.sections.score }}</template>
        <el-descriptions v-if="alertDetail?.score" :column="1" border>
          <el-descriptions-item label="综合评分">{{ alertDetail.score.scoreValue }}</el-descriptions-item>
          <el-descriptions-item label="风险等级">{{ getRiskLevelText(alertDetail.score.riskLevel) }}</el-descriptions-item>
          <el-descriptions-item label="评分原因">{{ alertDetail.score.scoreReason }}</el-descriptions-item>
        </el-descriptions>
        <el-empty v-else description="该预警未绑定任务评分，按实时流量行为独立触发。" />
      </el-card>
    </div>
  </section>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import { getSecurityAlertDetail } from '../../../../api/securityAlert'
import SecurityBreadcrumb from '../../../../components/security/SecurityBreadcrumb.vue'
import {
  getRiskLevelText,
  getSendStatusText,
  getTaskStatusText,
} from '../../../../constants/security'
import { securityPageContent } from '../../../../constants/securityContent'

const route = useRoute()
const router = useRouter()
const content = securityPageContent.alertDetail
const alertDetail = ref(null)
const loading = ref(false)
const errorMessage = ref('')

const alertId = computed(() => route.params.id)

// 来源类型中文映射：FLOW_MONITOR 表示来自实时监控（未绑定任务），TASK 表示任务检测触发
const formatSourceType = (value) => {
  if (value === 'FLOW_MONITOR') return '实时监控'
  if (value === 'TASK') return '任务检测'
  return value || '-'
}

// 加载预警详情；后端返回 'alert not found' 时统一替换为 notFound 文案，避免直接暴露英文错误
const loadAlertDetail = async () => {
  loading.value = true
  errorMessage.value = ''
  try {
    const resp = await getSecurityAlertDetail(alertId.value)
    alertDetail.value = resp.data.data
  } catch (error) {
    errorMessage.value = error.message === 'alert not found' ? content.notFound : error.message
  } finally {
    loading.value = false
  }
}

const goBack = () => {
  router.push('/security/alert')
}

onMounted(loadAlertDetail)
</script>

<style scoped>
.detail-grid {
  display: grid;
  gap: 16px;
}
</style>
