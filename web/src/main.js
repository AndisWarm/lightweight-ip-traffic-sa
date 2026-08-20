import { createApp } from 'vue'
// 按需从 element-plus/es/components 引入组件，只打包实际用到的部分，避免全量引入拖慢首屏。
import { ElAlert } from 'element-plus/es/components/alert/index.mjs'
import { ElBreadcrumb, ElBreadcrumbItem } from 'element-plus/es/components/breadcrumb/index.mjs'
import { ElButton } from 'element-plus/es/components/button/index.mjs'
import { ElCard } from 'element-plus/es/components/card/index.mjs'
import { ElCollapse, ElCollapseItem } from 'element-plus/es/components/collapse/index.mjs'
import { ElDescriptions, ElDescriptionsItem } from 'element-plus/es/components/descriptions/index.mjs'
import ElEmpty from 'element-plus/es/components/empty/index.mjs'
import { ElForm, ElFormItem } from 'element-plus/es/components/form/index.mjs'
import ElInput from 'element-plus/es/components/input/index.mjs'
import ElInputNumber from 'element-plus/es/components/input-number/index.mjs'
import ElLoading from 'element-plus/es/components/loading/index.mjs'
import ElPagination from 'element-plus/es/components/pagination/index.mjs'
import { ElRadioButton, ElRadioGroup } from 'element-plus/es/components/radio/index.mjs'
import { ElSelect, ElOption } from 'element-plus/es/components/select/index.mjs'
import ElSwitch from 'element-plus/es/components/switch/index.mjs'
import { ElTable, ElTableColumn } from 'element-plus/es/components/table/index.mjs'
import ElTag from 'element-plus/es/components/tag/index.mjs'
import 'element-plus/dist/index.css'
import './styles/theme.css'

import App from './App.vue'
import pinia from './pinia'
import router from './router'
import { installAuthExpiredListener } from './utils/auth-events'

// 创建根应用实例，随后依次挂载插件与全局组件，最后才 mount，保证依赖就绪后再渲染。
const app = createApp(App)

;[
  ElAlert,
  ElBreadcrumb,
  ElBreadcrumbItem,
  ElButton,
  ElCard,
  ElCollapse,
  ElCollapseItem,
  ElDescriptions,
  ElDescriptionsItem,
  ElEmpty,
  ElForm,
  ElFormItem,
  ElInput,
  ElInputNumber,
  ElOption,
  ElPagination,
  ElRadioButton,
  ElRadioGroup,
  ElSelect,
  ElSwitch,
  ElTable,
  ElTableColumn,
  ElTag,
// 逐个全局注册按需引入的组件（用组件自带的 name），这样模板里无需局部 import 即可直接使用。
].forEach((component) => {
  app.component(component.name, component)
})

// 依次注册 Pinia、路由与 Loading 指令；最后安装 401 事件监听器（需在路由就绪后），再挂载到 #app。
app.use(pinia)
app.use(router)
app.use(ElLoading)
installAuthExpiredListener()
app.mount('#app')
