<template>
  <main class="login-page">
    <section class="brand-panel">
      <div class="brand-mark">Q</div>
      <p class="eyebrow">QWEOVO Detect</p>
      <h1>流量检测控制台</h1>
      <p class="brand-copy">
        面向 SOCKS5 转发链路的 SNI、加密隧道与 Trojan 高危目标观测面板。
      </p>
      <div class="signal-list">
        <span>TCP Relay</span>
        <span>DPI Engine</span>
        <span>H2 Storage</span>
      </div>
    </section>

    <section class="login-card" aria-label="登录">
      <div class="card-head">
        <p class="eyebrow">Welcome back</p>
        <h2>登录 QWEOVO</h2>
      </div>

      <label class="field">
        <span>用户名</span>
        <input v-model="username" autocomplete="username" placeholder="admin" />
      </label>

      <label class="field">
        <span>密码</span>
        <input
          v-model="password"
          autocomplete="current-password"
          type="password"
          placeholder="请输入密码"
          @keyup.enter="handleLogin"
        />
      </label>

      <button class="login-btn" @click="handleLogin" :disabled="loading">
        <span>{{ loading ? '正在验证' : '进入控制台' }}</span>
        <span aria-hidden="true">→</span>
      </button>

      <p v-if="error" class="error">{{ error }}</p>
    </section>
  </main>
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
  if (!username.value || !password.value) {
    error.value = '请输入用户名和密码'
    return
  }

  loading.value = true
  error.value = ''

  try {
    await authStore.login({
      username: username.value,
      password: password.value
    })
    router.push('/')
  } catch (e) {
    error.value = e.response?.data?.error || '登录失败，请检查账号或密码'
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.login-page {
  min-height: 100vh;
  display: grid;
  grid-template-columns: minmax(0, 1.1fr) minmax(360px, 460px);
  background:
    radial-gradient(circle at 16% 18%, rgba(34, 197, 164, 0.16), transparent 30%),
    radial-gradient(circle at 88% 82%, rgba(245, 158, 11, 0.18), transparent 28%),
    linear-gradient(135deg, #f7faf8 0%, #eef4f1 48%, #f8f1e7 100%);
  color: #17211e;
}

.brand-panel {
  min-height: 100vh;
  padding: clamp(48px, 8vw, 96px);
  display: flex;
  flex-direction: column;
  justify-content: center;
}

.brand-mark {
  width: 64px;
  height: 64px;
  display: grid;
  place-items: center;
  border-radius: 18px;
  background: #15352f;
  color: #d9fff4;
  font-size: 34px;
  font-weight: 800;
  box-shadow: 0 18px 42px rgba(21, 53, 47, 0.22);
}

.eyebrow {
  margin-top: 28px;
  color: #55746d;
  font-size: 12px;
  font-weight: 800;
  letter-spacing: 0.12em;
  text-transform: uppercase;
}

.brand-panel h1 {
  max-width: 640px;
  margin: 14px 0 16px;
  font-size: clamp(42px, 6vw, 74px);
  line-height: 1.02;
  font-weight: 850;
  letter-spacing: 0;
}

.brand-copy {
  max-width: 560px;
  color: #4d625d;
  font-size: 17px;
  line-height: 1.8;
}

.signal-list {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  margin-top: 34px;
}

.signal-list span {
  padding: 9px 12px;
  border-radius: 999px;
  background: rgba(255, 255, 255, 0.72);
  border: 1px solid rgba(21, 53, 47, 0.1);
  color: #29433d;
  font-size: 13px;
  font-weight: 700;
}

.login-card {
  align-self: center;
  margin-right: clamp(28px, 6vw, 88px);
  padding: 34px;
  border: 1px solid rgba(21, 53, 47, 0.12);
  border-radius: 8px;
  background: rgba(255, 255, 255, 0.78);
  box-shadow: 0 24px 70px rgba(24, 44, 38, 0.14);
  backdrop-filter: blur(18px);
}

.card-head {
  margin-bottom: 28px;
}

.card-head .eyebrow {
  margin-top: 0;
}

.card-head h2 {
  margin-top: 8px;
  color: #17211e;
  font-size: 28px;
  font-weight: 820;
}

.field {
  display: grid;
  gap: 8px;
  margin-bottom: 18px;
}

.field span {
  color: #47625b;
  font-size: 13px;
  font-weight: 750;
}

.field input {
  width: 100%;
  height: 48px;
  padding: 0 14px;
  border: 1px solid #c9d8d3;
  border-radius: 8px;
  background: #fbfefd;
  color: #17211e;
  font-size: 15px;
  outline: none;
  transition: border-color 0.18s, box-shadow 0.18s;
}

.field input:focus {
  border-color: #1f9f83;
  box-shadow: 0 0 0 4px rgba(31, 159, 131, 0.12);
}

.login-btn {
  width: 100%;
  height: 50px;
  margin-top: 6px;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 10px;
  border: 0;
  border-radius: 8px;
  background: #15352f;
  color: #ffffff;
  cursor: pointer;
  font-size: 15px;
  font-weight: 800;
  transition: transform 0.18s, box-shadow 0.18s, background 0.18s;
}

.login-btn:hover:not(:disabled) {
  transform: translateY(-1px);
  background: #1d4a41;
  box-shadow: 0 14px 32px rgba(21, 53, 47, 0.2);
}

.login-btn:disabled {
  cursor: wait;
  opacity: 0.72;
}

.error {
  margin-top: 16px;
  padding: 10px 12px;
  border-radius: 8px;
  background: #fff1f0;
  color: #b42318;
  font-size: 13px;
}

@media (max-width: 860px) {
  .login-page {
    grid-template-columns: 1fr;
    padding: 24px;
  }

  .brand-panel {
    min-height: auto;
    padding: 28px 0;
  }

  .brand-panel h1 {
    font-size: 42px;
  }

  .login-card {
    width: 100%;
    margin: 0;
  }
}
</style>
