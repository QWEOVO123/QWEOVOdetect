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
        <span>{{ setupMode ? 'Database Setup' : 'H2 / MySQL' }}</span>
      </div>
    </section>

    <section v-if="setupMode" class="login-card setup-card" aria-label="数据库初始化">
      <div class="card-head">
        <p class="eyebrow">First startup</p>
        <h2>初始化系统</h2>
      </div>

      <label class="field">
        <span>初始用户名</span>
        <input v-model="initialAuth.username" autocomplete="username" placeholder="请输入用户名" />
      </label>

      <label class="field">
        <span>初始密码</span>
        <input v-model="initialAuth.password" type="password" autocomplete="new-password" placeholder="请输入密码" />
      </label>

      <label class="field">
        <span>确认初始密码</span>
        <input v-model="initialAuth.confirmPassword" type="password" autocomplete="new-password" placeholder="请再次输入密码" />
      </label>

      <div class="setup-section">
        <div class="setup-section-head">
          <strong>API 端口</strong>
          <span>保存后重启生效</span>
        </div>
        <label class="field">
          <span>API 监听端口</span>
          <input v-model.number="apiForm.port" type="number" min="1" max="65535" placeholder="8080" />
        </label>
      </div>

      <div class="setup-section">
        <div class="setup-section-head">
          <strong>SOCKS5 入站</strong>
          <button type="button" class="mini-btn" @click="addInbound">添加入站</button>
        </div>
        <div v-for="(inbound, index) in inboundForms" :key="inbound.id || index" class="inbound-card">
          <div class="inbound-card-head">
            <strong>入站 {{ index + 1 }}</strong>
            <button v-if="inboundForms.length > 1" type="button" class="mini-btn danger" @click="removeInbound(index)">删除</button>
          </div>
          <label class="field">
            <span>昵称</span>
            <input v-model="inbound.nickname" placeholder="默认入站" />
          </label>
          <label class="field">
            <span>监听端口</span>
            <input v-model.number="inbound.port" type="number" min="1" max="65535" placeholder="1080" />
          </label>
          <label class="check-row">
            <input v-model="inbound.enabled" type="checkbox" />
            <span>启用这个入站</span>
          </label>
          <label class="check-row">
            <input v-model="inbound.authEnabled" type="checkbox" />
            <span>启用 SOCKS5 用户名密码认证</span>
          </label>
          <template v-if="inbound.authEnabled">
            <label class="field">
              <span>SOCKS5 用户名</span>
              <input v-model="inbound.username" autocomplete="username" />
            </label>
            <label class="field">
              <span>SOCKS5 密码</span>
              <input v-model="inbound.password" type="password" autocomplete="new-password" />
            </label>
          </template>
        </div>
      </div>

      <div class="segment">
        <button :class="{ active: dbForm.type === 'H2' }" @click="dbForm.type = 'H2'">H2</button>
        <button :class="{ active: dbForm.type === 'MYSQL' }" @click="dbForm.type = 'MYSQL'">MySQL</button>
      </div>

      <label v-if="dbForm.type === 'H2'" class="field">
        <span>H2 数据路径</span>
        <input v-model="dbForm.path" placeholder="./data/socks5_stats" />
      </label>

      <template v-else>
        <label class="field">
          <span>MySQL 地址</span>
          <input v-model="dbForm.host" placeholder="127.0.0.1" />
        </label>
        <label class="field">
          <span>MySQL 端口</span>
          <input v-model.number="dbForm.port" type="number" min="1" max="65535" placeholder="3306" />
        </label>
        <label class="field">
          <span>数据库名</span>
          <input v-model="dbForm.databaseName" placeholder="qweovo_detect" />
        </label>
        <label class="field">
          <span>用户名</span>
          <input v-model="dbForm.username" autocomplete="username" />
        </label>
        <label class="field">
          <span>密码</span>
          <input v-model="dbForm.password" type="password" autocomplete="current-password" />
        </label>
      </template>

      <button class="login-btn" @click="saveSetup" :disabled="setupSaving">
        <span>{{ setupSaving ? '正在保存' : '保存数据库配置' }}</span>
      </button>

      <p v-if="setupMessage" class="notice" :class="{ warn: setupRequiresRestart }">{{ setupMessage }}</p>
      <p v-if="error" class="error">{{ error }}</p>
    </section>

    <section v-else class="login-card" aria-label="登录">
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
import { onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '../stores/auth'

const router = useRouter()
const authStore = useAuthStore()

const username = ref('')
const password = ref('')
const loading = ref(false)
const error = ref('')
const setupMode = ref(false)
const setupSaving = ref(false)
const setupMessage = ref('')
const setupRequiresRestart = ref(false)
const initialAuth = ref({
  username: '',
  password: '',
  confirmPassword: ''
})
const dbForm = ref({
  type: 'H2',
  path: './data/socks5_stats',
  host: '127.0.0.1',
  port: 3306,
  databaseName: '',
  username: '',
  password: ''
})
const apiForm = ref({
  address: '127.0.0.1',
  port: 8080
})
const inboundForms = ref([newInbound()])

onMounted(async () => {
  try {
    const status = await authStore.setupStatus()
    setupMode.value = Boolean(status.firstStartup)
    applyDatabase(status.database)
    applyRuntime(status)
  } catch (e) {
    setupMode.value = false
  }
})

function newInbound() {
  return {
    id: crypto.randomUUID ? crypto.randomUUID() : String(Date.now() + Math.random()),
    nickname: '默认入站',
    port: 1080,
    enabled: true,
    authEnabled: false,
    username: '',
    password: ''
  }
}

function addInbound() {
  inboundForms.value.push({
    ...newInbound(),
    nickname: `入站 ${inboundForms.value.length + 1}`,
    port: 1080 + inboundForms.value.length
  })
}

function removeInbound(index) {
  inboundForms.value.splice(index, 1)
}

function applyRuntime(status) {
  if (status.api) {
    apiForm.value = {
      address: status.api.address || '127.0.0.1',
      port: status.api.port || 8080
    }
  }
  if (Array.isArray(status.inbounds) && status.inbounds.length) {
    inboundForms.value = status.inbounds.map(inbound => ({
      id: inbound.id,
      nickname: inbound.nickname || `入站 ${inbound.port || 1080}`,
      port: inbound.port || 1080,
      enabled: inbound.enabled !== false,
      authEnabled: Boolean(inbound.authEnabled),
      username: inbound.username || '',
      password: ''
    }))
  }
}

function applyDatabase(database) {
  if (!database) return
  dbForm.value = {
    type: database.type || 'H2',
    path: database.path || './data/socks5_stats',
    host: database.host || '127.0.0.1',
    port: database.port || 3306,
    databaseName: database.databaseName || '',
    username: database.username || '',
    password: ''
  }
}

async function saveSetup() {
  error.value = ''
  setupMessage.value = ''
  setupRequiresRestart.value = false

  if (dbForm.value.type === 'MYSQL' && (!dbForm.value.databaseName || !dbForm.value.username)) {
    error.value = '请填写 MySQL 数据库名和用户名'
    return
  }
  if (!initialAuth.value.username || !initialAuth.value.password) {
    error.value = '请设置初始用户名和密码'
    return
  }
  if (initialAuth.value.password !== initialAuth.value.confirmPassword) {
    error.value = '两次输入的初始密码不一致'
    return
  }

  const inboundError = validateInbounds()
  if (inboundError) {
    error.value = inboundError
    return
  }

  setupSaving.value = true
  try {
    const result = await authStore.saveDatabaseSetup({
      initialUsername: initialAuth.value.username,
      initialPassword: initialAuth.value.password,
      database: dbPayload(),
      api: apiPayload(),
      inbounds: inboundPayload()
    })
    setupRequiresRestart.value = result.requiresRestart
    setupMessage.value = result.requiresRestart
      ? '数据库配置已保存，请重启后端服务后再登录。'
      : '数据库配置已保存，可以继续登录。'
    setupMode.value = Boolean(result.requiresRestart)
  } catch (e) {
    error.value = e.response?.data?.error || '保存数据库配置失败'
  } finally {
    setupSaving.value = false
  }
}

function dbPayload() {
  if (dbForm.value.type === 'H2') {
    return {
      type: 'H2',
      path: dbForm.value.path
    }
  }

  return {
    type: 'MYSQL',
    host: dbForm.value.host,
    port: Number(dbForm.value.port || 3306),
    databaseName: dbForm.value.databaseName,
    username: dbForm.value.username,
    password: dbForm.value.password
  }
}

function validateInbounds() {
  if (!apiForm.value.port || apiForm.value.port < 1 || apiForm.value.port > 65535) {
    return 'API 端口必须在 1-65535 之间'
  }
  if (!inboundForms.value.some(inbound => inbound.enabled)) {
    return '至少需要启用一个入站端口'
  }
  const ports = new Set()
  for (const inbound of inboundForms.value) {
    if (!inbound.port || inbound.port < 1 || inbound.port > 65535) {
      return '入站端口必须在 1-65535 之间'
    }
    if (ports.has(Number(inbound.port))) {
      return `入站端口不能重复：${inbound.port}`
    }
    ports.add(Number(inbound.port))
    if (inbound.enabled && Number(inbound.port) === Number(apiForm.value.port)) {
      return 'API 端口不能和启用的入站端口相同'
    }
    if (inbound.authEnabled && (!inbound.username || !inbound.password)) {
      return '启用 SOCKS5 认证时必须填写用户名和密码'
    }
  }
  return ''
}

function apiPayload() {
  return {
    address: apiForm.value.address || '127.0.0.1',
    port: Number(apiForm.value.port || 8080)
  }
}

function inboundPayload() {
  return inboundForms.value.map(inbound => ({
    id: inbound.id,
    nickname: inbound.nickname,
    port: Number(inbound.port),
    enabled: Boolean(inbound.enabled),
    authEnabled: Boolean(inbound.authEnabled),
    username: inbound.username,
    password: inbound.password
  }))
}

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

.setup-card {
  align-self: center;
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

.segment {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 8px;
  margin-bottom: 18px;
  padding: 4px;
  border-radius: 8px;
  background: #edf5f2;
}

.segment button {
  height: 38px;
  border: 0;
  border-radius: 7px;
  background: transparent;
  color: #47625b;
  cursor: pointer;
  font-weight: 800;
}

.segment button.active {
  background: #ffffff;
  color: #15352f;
  box-shadow: 0 8px 20px rgba(24, 44, 38, 0.08);
}

.setup-section {
  margin-bottom: 18px;
  padding: 14px;
  border: 1px solid #dbe8e3;
  border-radius: 8px;
  background: rgba(250, 253, 252, 0.82);
}

.setup-section-head,
.inbound-card-head,
.check-row {
  display: flex;
  align-items: center;
}

.setup-section-head,
.inbound-card-head {
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 12px;
}

.setup-section-head strong,
.inbound-card-head strong {
  color: #203a34;
}

.setup-section-head span {
  color: #78908a;
  font-size: 12px;
  font-weight: 750;
}

.inbound-card {
  padding: 12px;
  border: 1px solid #e4eeea;
  border-radius: 8px;
  background: #ffffff;
}

.inbound-card + .inbound-card {
  margin-top: 10px;
}

.mini-btn {
  height: 30px;
  padding: 0 10px;
  border: 1px solid #cfddd8;
  border-radius: 7px;
  background: #ffffff;
  color: #24443d;
  cursor: pointer;
  font-weight: 800;
}

.mini-btn.danger {
  border-color: #fecdd3;
  color: #be123c;
}

.check-row {
  gap: 8px;
  margin-bottom: 12px;
  color: #47625b;
  font-size: 13px;
  font-weight: 750;
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

.error,
.notice {
  margin-top: 16px;
  padding: 10px 12px;
  border-radius: 8px;
  font-size: 13px;
}

.error {
  background: #fff1f0;
  color: #b42318;
}

.notice {
  background: #def7ec;
  color: #047857;
}

.notice.warn {
  background: #fff0cc;
  color: #b45309;
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
