<template>
  <section class="sa-page">
    <SecurityBreadcrumb />

    <header class="sa-page-header">
      <div>
        <h1>用户管理</h1>
        <p>用于维护平台用户、角色分级与账号启用状态，仅 Admin 可访问。</p>
      </div>
      <el-tag type="danger">系统管理</el-tag>
    </header>

    <el-card class="sa-panel" shadow="never">
      <template #header>新增用户</template>

      <el-form :model="form" inline>
        <el-form-item label="用户名">
          <el-input v-model="form.username" placeholder="请输入用户名" />
        </el-form-item>
        <el-form-item label="显示名称">
          <el-input v-model="form.displayName" placeholder="请输入显示名称" />
        </el-form-item>
        <el-form-item label="密码">
          <el-input v-model="form.password" type="password" show-password placeholder="请输入初始密码" />
        </el-form-item>
        <el-form-item label="角色">
          <el-select v-model="form.roleCode" style="width: 180px">
            <el-option label="Admin" value="ADMIN" />
            <el-option label="Manager" value="MANAGER" />
            <el-option label="User" value="USER" />
          </el-select>
        </el-form-item>
        <el-form-item label="启用">
          <el-switch v-model="form.enable" />
        </el-form-item>
        <el-form-item>
          <el-button type="primary" :loading="submitting" @click="handleCreate">新增用户</el-button>
        </el-form-item>
      </el-form>
    </el-card>

    <el-card class="sa-panel list-panel" shadow="never">
      <template #header>用户列表</template>

      <el-alert
        v-if="errorMessage"
        class="sa-table-alert"
        type="error"
        :closable="false"
        :title="errorMessage"
      />

      <el-table v-loading="loading" :data="users" border>
        <el-table-column prop="id" label="用户 ID" width="90" />
        <el-table-column prop="username" label="用户名" min-width="140" />
        <el-table-column prop="displayName" label="显示名称" min-width="160" />
        <el-table-column prop="roleName" label="角色" width="140" />
        <el-table-column label="状态" width="110">
          <template #default="{ row }">
            <el-tag :type="row.enable ? 'success' : 'danger'">{{ row.enable ? '启用' : '禁用' }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="createdAt" label="创建时间" min-width="180" />
        <el-table-column label="操作" width="240" fixed="right">
          <template #default="{ row }">
            <el-button link type="primary" @click="toggleUser(row)">
              {{ row.enable ? '禁用账号' : '启用账号' }}
            </el-button>
            <el-button link type="warning" @click="resetPassword(row)">重置密码</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>
  </section>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'

import SecurityBreadcrumb from '../../../components/security/SecurityBreadcrumb.vue'
import { useUserStore } from '../../../pinia/modules/user'

const userStore = useUserStore()
const users = ref([])
const loading = ref(false)
const submitting = ref(false)
const errorMessage = ref('')

// 新增用户表单默认值：密码统一初始化为 Admin123!，角色默认 MANAGER，账号默认启用
const createDefaultForm = () => ({
  username: '',
  displayName: '',
  password: 'Admin123!',
  roleCode: 'MANAGER',
  enable: true,
})

const form = reactive(createDefaultForm())

// 拉取用户列表（数据来自 userStore.fetchUserList）
const loadUsers = async () => {
  loading.value = true
  errorMessage.value = ''
  try {
    users.value = await userStore.fetchUserList()
  } catch (error) {
    errorMessage.value = error.message
  } finally {
    loading.value = false
  }
}

// 新增用户：前端先做必填校验，成功后重置表单并刷新列表
const handleCreate = async () => {
  if (!form.username || !form.displayName || !form.password) {
    ElMessage.warning('请完整填写新增用户信息')
    return
  }

  submitting.value = true
  try {
    await userStore.createUserAction({ ...form })
    ElMessage.success('用户创建成功')
    Object.assign(form, createDefaultForm())
    await loadUsers()
  } catch (error) {
    ElMessage.error(error.message)
  } finally {
    submitting.value = false
  }
}

// 启用/禁用账号：调用 store 的 updateUserStatusAction 取反当前状态后刷新列表
const toggleUser = async (row) => {
  try {
    await userStore.updateUserStatusAction(row.id, !row.enable)
    ElMessage.success('用户状态更新成功')
    await loadUsers()
  } catch (error) {
    ElMessage.error(error.message)
  } finally {
    loading.value = false
  }
}

// 重置密码为默认值 Admin123!：先弹确认框，取消（error === 'cancel'）时静默忽略
const resetPassword = async (row) => {
  try {
    await ElMessageBox.confirm(
      `确认将用户 ${row.username} 的密码重置为 Admin123! 吗？`,
      '重置密码确认',
      { type: 'warning' }
    )
    await userStore.resetPasswordAction(row.id, 'Admin123!')
    ElMessage.success('密码重置成功')
  } catch (error) {
    if (error !== 'cancel') {
      ElMessage.error(error.message || '密码重置失败')
    }
  }
}

onMounted(loadUsers)
</script>

<style scoped>
.list-panel {
  margin-top: 16px;
}
</style>
