import { defineStore } from 'pinia'

// 安全域共享状态：只放跨页面需要共享的 UI 态（总览时间范围、当前选中任务/预警 id），
// 让列表页跳详情页时能记住上下文，避免用 URL 传一堆临时参数。
export const useSecurityStore = defineStore('security', {
  state: () => ({
    dashboardFilter: '7d',
    selectedTaskId: '',
    selectedAlertId: '',
  }),
  actions: {
    setDashboardFilter(value) {
      this.dashboardFilter = value
    },
    setSelectedTaskId(value) {
      this.selectedTaskId = value
    },
    setSelectedAlertId(value) {
      this.selectedAlertId = value
    },
  },
})
