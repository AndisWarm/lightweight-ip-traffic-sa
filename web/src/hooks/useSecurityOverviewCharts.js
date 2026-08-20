import { computed } from 'vue'
import { use } from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'
import { LineChart, PieChart, ScatterChart, MapChart } from 'echarts/charts'
import {
  GridComponent,
  GeoComponent,
  TooltipComponent,
  LegendComponent,
} from 'echarts/components'

import { getRiskLevelText } from '../constants/security'

use([CanvasRenderer, LineChart, PieChart, ScatterChart, MapChart, GridComponent, GeoComponent, TooltipComponent, LegendComponent])

export const useSecurityOverviewCharts = (summary) => {
  const trendSeries = computed(() => {
    const trend = Array.isArray(summary.value?.trend) ? summary.value.trend : []
    return {
      days: trend.map((item) => item.date),
      taskValues: trend.map((item) => item.taskCount || 0),
      alertValues: trend.map((item) => item.alertCount || 0),
    }
  })

  const riskDistribution = computed(() => {
    const distribution = Array.isArray(summary.value?.riskDistribution) ? summary.value.riskDistribution : []
    return distribution
      .filter((item) => item.count > 0)
      .map((item) => ({
        name: getRiskLevelText(item.riskLevel),
        value: item.count,
      }))
  })

  const hasTrendData = computed(() => (
    trendSeries.value.taskValues.some((value) => value > 0) ||
    trendSeries.value.alertValues.some((value) => value > 0)
  ))
  const hasDistributionData = computed(() => riskDistribution.value.length > 0)

  const trendOption = computed(() => ({
    tooltip: {
      trigger: 'axis',
    },
    legend: {
      data: ['检测任务', '预警事件'],
    },
    grid: {
      left: 40,
      right: 20,
      top: 40,
      bottom: 30,
    },
    xAxis: {
      type: 'category',
      data: trendSeries.value.days,
    },
    yAxis: {
      type: 'value',
      minInterval: 1,
    },
    series: [
      {
        name: '检测任务',
        type: 'line',
        smooth: true,
        data: trendSeries.value.taskValues,
        color: '#12344d',
      },
      {
        name: '预警事件',
        type: 'line',
        smooth: true,
        data: trendSeries.value.alertValues,
        color: '#d84f3f',
      },
    ],
  }))

  const distributionOption = computed(() => ({
    tooltip: {
      trigger: 'item',
    },
    legend: {
      bottom: 0,
    },
    series: [
      {
        name: '风险等级分布',
        type: 'pie',
        radius: ['40%', '68%'],
        center: ['50%', '45%'],
        data: riskDistribution.value,
        label: {
          formatter: '{b}: {c}',
        },
      },
    ],
  }))

  return {
    hasTrendData,
    hasDistributionData,
    trendOption,
    distributionOption,
  }
}
