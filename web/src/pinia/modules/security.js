import { defineStore } from 'pinia'

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
