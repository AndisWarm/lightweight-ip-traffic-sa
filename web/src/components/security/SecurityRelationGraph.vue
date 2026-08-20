<template>
  <div class="relation-graph">
    <VChart v-if="hasGraphData" :option="graphOption" autoresize class="graph-chart" />
    <el-empty v-else description="当前任务暂无可视化关联图谱数据" />
  </div>
</template>

<script setup>
import { computed } from 'vue'
import VChart from 'vue-echarts'
import { use } from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'
import { GraphChart } from 'echarts/charts'
import { TooltipComponent, LegendComponent } from 'echarts/components'

use([CanvasRenderer, GraphChart, TooltipComponent, LegendComponent])

const props = defineProps({
  graph: {
    type: Object,
    default: () => ({ nodes: [], edges: [] }),
  },
})

// 节点分类元信息：把后端返回的 category 字符串映射为中文名、颜色与节点大小，
// 让关系图里目标 IP / 对端 IP / 协议 / 端口 / 主机头等不同类型一眼可区分
const categoryMeta = {
  'target-ip': { name: '目标 IP', color: '#12344d', symbolSize: 58 },
  'peer-ip': { name: '对端 IP', color: '#3a7afe', symbolSize: 40 },
  protocol: { name: '协议', color: '#12a594', symbolSize: 34 },
  port: { name: '端口', color: '#ef7d57', symbolSize: 32 },
  'http-host': { name: 'HTTP Host', color: '#7a4ff2', symbolSize: 36 },
  'tls-sni': { name: 'TLS SNI', color: '#cc3f7a', symbolSize: 36 },
}

const hasGraphData = computed(() => {
  return Array.isArray(props.graph?.nodes) && props.graph.nodes.length > 0
})

const categories = computed(() => {
  const keys = [...new Set((props.graph?.nodes || []).map((item) => item.category).filter(Boolean))]
  return keys.map((key) => ({
    name: categoryMeta[key]?.name || key,
  }))
})

const categoryIndexMap = computed(() => {
  const map = new Map()
  categories.value.forEach((item, index) => {
    map.set(item.name, index)
  })
  return map
})

// ECharts 力导向关系图 option：把 props.graph 的 nodes/edges 转成带分类、权重、边标签的图数据，
// 节点大小随 value 权重放大、边线宽随关系权重加粗，便于直观看出哪些节点是聚合核心
const graphOption = computed(() => {
  const nodes = (props.graph?.nodes || []).map((node) => {
    const meta = categoryMeta[node.category] || { name: node.category || '节点', color: '#5b6b7a', symbolSize: 28 }
    return {
      id: node.id,
      name: node.label,
      value: node.value,
      category: categoryIndexMap.value.get(meta.name) ?? 0,
      symbolSize: Math.max(meta.symbolSize, Math.min(72, meta.symbolSize + Math.round(Number(node.value || 0) / 3))),
      itemStyle: { color: meta.color },
      meta: node.meta || {},
    }
  })

  const links = (props.graph?.edges || []).map((edge) => ({
    source: edge.source,
    target: edge.target,
    value: edge.value,
    label: {
      show: true,
      formatter: edge.label || '',
      fontSize: 11,
      color: '#425466',
    },
    lineStyle: {
      width: Math.max(1, Math.min(5, Number(edge.value || 1) / 5)),
      opacity: 0.7,
      color: '#93a4b2',
      curveness: 0.12,
    },
  }))

  return {
    tooltip: {
      formatter: (params) => {
        if (params.dataType === 'edge') {
          return `${params.data.source} → ${params.data.target}<br/>关系=${params.data.label?.formatter || '-'}`
        }
        const data = params.data || {}
        return `${data.name}<br/>类型=${categories.value[data.category]?.name || '-'}<br/>权重=${data.value || 0}`
      },
    },
    legend: {
      bottom: 0,
      data: categories.value.map((item) => item.name),
    },
    series: [
      {
        type: 'graph',
        layout: 'force',
        roam: true,
        draggable: true,
        force: {
          repulsion: 280,
          edgeLength: [80, 160],
        },
        label: {
          show: true,
          position: 'right',
          color: '#1f2d3d',
          fontSize: 12,
        },
        categories: categories.value,
        data: nodes,
        links,
      },
    ],
  }
})
</script>

<style scoped>
.relation-graph {
  min-height: 360px;
}

.graph-chart {
  height: 360px;
}
</style>
