<template>
  <div class="login-bg">
    <div class="login-card">
      <div class="login-icon">🍞</div>
      <h1>QWEOVO</h1>
      <p class="subtitle">小面包流量检测站</p>
      
      <div class="form-item">
        <input v-model="username" placeholder="用户名" class="my-input" />
      </div>
      <div class="form-item">
        <input v-model="password" type="password" placeholder="密码" class="my-input" @keyup.enter="handleLogin" />
      </div>
      <div class="form-item">
        <button class="my-btn" @click="handleLogin" :disabled="loading">
          <span v-if="loading">正在开门...</span>
          <span v-else>🚪 进门</span>
        </button>
      </div>

      <p v-if="error" class="error">😿 {{ error }}</p>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '../stores/auth'

const router = useRouter()
const authStore = useAuthStore()

const username = ref('')
const password = ref('')
const loading = ref(false)
const error = ref('')

async function handleLogin() {
  console.log('=== 点击了登录按钮 ===')
  console.log('username:', username.value)
  console.log('password:', password.value)

  if (!username.value || !password.value) {
    error.value = '请输入用户名和密码'
    console.log('验证失败：用户名或密码为空')
    return
  }

  loading.value = true
  error.value = ''
  
  console.log('准备发送请求...')
  
  try {
    const res = await authStore.login({
      username: username.value,
      password: password.value
    })
    console.log('登录成功！', res)
    router.push('/')
  } catch (e) {
    console.error('登录失败，完整错误：', e)
    console.error('错误响应：', e.response)
    error.value = e.response?.data?.error || '再试试？'
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.login-bg {
  display: flex;
  justify-content: center;
  align-items: center;
  height: 100vh;
  background: linear-gradient(135deg, #fff8e7 0%, #fff3e0 50%, #fef0db 100%);
}
.login-card {
  width: 400px;
  padding: 48px 40px;
  background: #fffdf7;
  border: 1px solid #e8d5c4;
  border-radius: 24px;
  text-align: center;
  box-shadow: 0 8px 32px rgba(139, 90, 43, 0.08);
}
.login-icon {
  font-size: 56px;
  margin-bottom: 8px;
}
h1 {
  color: #6d4c41;
  font-size: 28px;
  font-weight: 800;
  letter-spacing: 2px;
  margin-bottom: 4px;
}
.subtitle {
  color: #a1887f;
  font-size: 14px;
  margin-bottom: 32px;
}
.form-item {
  margin-bottom: 18px;
}
.my-input {
  width: 100%;
  padding: 14px 16px;
  border: 2px solid #e8d5c4;
  border-radius: 12px;
  font-size: 15px;
  outline: none;
  box-sizing: border-box;
  background: #fffef9;
  color: #5d4037;
  transition: border-color 0.2s;
}
.my-input:focus {
  border-color: #ffb74d;
}
.my-btn {
  width: 100%;
  padding: 14px;
  background: #ffb74d;
  color: #fff;
  border: none;
  border-radius: 25px;
  font-size: 16px;
  font-weight: 700;
  cursor: pointer;
  transition: all 0.2s;
  letter-spacing: 2px;
}
.my-btn:hover {
  background: #ffa726;
}
.my-btn:disabled {
  background: #ffcc80;
  cursor: not-allowed;
}
.error {
  color: #d84315;
  font-size: 14px;
  margin-top: 12px;
}
</style>