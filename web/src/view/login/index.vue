<template>
  <section class="login-page">
    <div class="login-panel">
      <div class="login-intro">
        <p class="eyebrow">轻量化安全态势感知平台</p>
        <h1>用户登录</h1>
        <p class="description">
          登录后可进入轻量化 IP-流量多特征融合态势感知系统，查看态势总览、检测任务、预警中心与用户管理功能。
        </p>
      </div>

      <el-form
        ref="formRef"
        :model="form"
        :rules="rules"
        label-position="top"
        class="login-form"
        @submit.prevent="handleLogin"
      >
        <el-form-item label="用户名" prop="username">
          <el-input v-model="form.username" placeholder="请输入用户名" @keyup.enter="handleLogin" />
        </el-form-item>
        <el-form-item label="密码" prop="password">
          <el-input v-model="form.password" type="password" show-password placeholder="请输入密码" @keyup.enter="handleLogin" />
        </el-form-item>
        <el-button type="primary" native-type="submit" class="submit-btn" :loading="submitting" @click="handleLogin">
          登录
        </el-button>
      </el-form>

      <el-alert
        class="demo-tip"
        type="info"
        :closable="false"
        title="演示账号：admin / manager / user"
        description="初始密码均为：Admin123!"
      />
    </div>
  </section>
</template>

<script setup>
import { reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { useRouter } from 'vue-router'

import { useUserStore } from '../../pinia/modules/user'

const router = useRouter()
const userStore = useUserStore()
const formRef = ref()
const submitting = ref(false)
const form = reactive({
  username: 'admin',
  password: 'Admin123!',
})

// 表单校验规则：用户名与密码均为必填，失焦时触发校验，避免空值直接提交到后端
const rules = {
  username: [{ required: true, message: '请输入用户名', trigger: 'blur' }],
  password: [{ required: true, message: '请输入密码', trigger: 'blur' }],
}

// 登录核心流程：先做本地表单校验，再通过 Pinia 的 loginByPassword 换取并持久化 token，
// 成功后用 replace 跳转（避免登录页残留在历史记录里可被后退回到）
const handleLogin = async () => {
  // submitting 防抖：登录请求未返回前禁止重复提交
  if (submitting.value) {
    return
  }

  try {
    await formRef.value.validate()
    submitting.value = true
    await userStore.loginByPassword(form)
    ElMessage.success('登录成功')
    router.replace('/security/overview')
  } catch (error) {
    if (error?.message) {
      ElMessage.error(error.message)
    }
  } finally {
    submitting.value = false
  }
}
</script>

<style scoped>
.login-page {
  min-height: 100vh;
  display: grid;
  place-items: center;
  background:
    radial-gradient(circle at top left, rgba(18, 52, 77, 0.22), transparent 32%),
    linear-gradient(180deg, #eef5fb 0%, #dce8f3 100%);
  padding: 24px;
}

.login-panel {
  width: min(460px, 100%);
  padding: 36px;
  border-radius: 24px;
  background: rgba(255, 255, 255, 0.95);
  box-shadow: 0 24px 60px rgba(18, 52, 77, 0.18);
}

.login-intro {
  margin-bottom: 24px;
}

.eyebrow {
  margin: 0 0 8px;
  color: #2e6288;
  font-size: 13px;
  font-weight: 600;
  letter-spacing: 0.08em;
}

.login-intro h1 {
  margin: 0 0 10px;
  font-size: 30px;
  color: #12344d;
}

.description {
  margin: 0;
  color: #587086;
  line-height: 1.8;
}

.login-form {
  margin-bottom: 20px;
}

.submit-btn {
  width: 100%;
  margin-top: 10px;
}

.demo-tip {
  margin-top: 10px;
}
</style>
