<template>
  <div class="dashboard-shell">
    <header class="topbar">
      <div class="brand">
        <div class="brand-mark">Q</div>
        <div>
          <p>QWEOVO Detect</p>
          <h1>流量检测控制台</h1>
        </div>
      </div>

      <div class="top-actions">
        <span class="status-dot"></span>
        <span class="time">{{ nowTime }}</span>
        <span class="user">{{ authStore.username }}</span>
        <button class="secondary-btn" @click="openRuntimeDialog" title="修改 API 端口和入站配置">入站设置</button>
        <button class="secondary-btn" @click="openDatabaseDialog" title="修改数据库配置">数据库设置</button>
        <button class="secondary-btn" @click="openCredentialDialog" title="修改用户名和密码">账号设置</button>
        <button class="logout-btn" @click="handleLogout" title="退出登录">退出</button>
      </div>
    </header>

    <main class="dashboard-main">
      <section class="intro">
        <div>
          <p class="eyebrow">{{ greeting }}</p>
          <h2>代理流量态势</h2>
        </div>
        <p class="intro-copy">
          实时汇总 SNI、加密隧道、Trojan 命中和高危目标，数据每 10 秒自动刷新。
        </p>
      </section>

      <section class="metrics-grid">
        <article v-for="item in metrics" :key="item.label" class="metric-card" :class="item.tone">
          <div class="metric-icon">{{ item.icon }}</div>
          <div>
            <p>{{ item.label }}</p>
            <strong>{{ item.value }}</strong>
          </div>
        </article>
      </section>

      <section class="panel port-panel">
        <div class="panel-head">
          <div>
            <p class="eyebrow">Ports</p>
            <h3>SOCKS5 端口用户概览</h3>
          </div>
          <span class="hint">按入站端口独立统计</span>
        </div>
        <div class="port-grid">
          <article v-for="port in portSummary" :key="port.listenPort" class="port-card">
            <div class="port-head">
              <strong>{{ port.listenPort }}</strong>
              <span :class="{ active: hasPortTraffic(port) }">{{ hasPortTraffic(port) ? '有流量' : '待机' }}</span>
            </div>
            <div class="port-stats">
              <span>SNI {{ port.sniTotal }}</span>
              <span>客户端 {{ port.clientCount }}</span>
              <span>异常 {{ Number(port.ssTotal || 0) + Number(port.trojanTotal || 0) }}</span>
              <span>高危 {{ port.riskCount }}</span>
            </div>
            <div class="port-domains" v-if="port.topDomains?.length">
              <span v-for="domain in port.topDomains" :key="`${port.listenPort}-${domain.protocol}-${domain.domain}`">
                <b :class="protocolClass(domain.protocol)">{{ domain.protocol || 'TLS' }}</b>
                {{ domain.domain }} · {{ domain.count }}
              </span>
            </div>
          </article>
        </div>
      </section>

      <section class="panel block-panel">
        <div class="panel-head">
          <div>
            <p class="eyebrow">Block List</p>
            <h3>封禁规则</h3>
          </div>
          <span class="hint">{{ blockRules.length }} 条规则</span>
        </div>
        <div class="block-group-title">域名关键词封禁</div>
        <form class="block-form" @submit.prevent="addBlockRule">
          <input v-model="blockKeyword" placeholder="输入关键词，例如 tiktok" maxlength="128" />
          <button class="primary-btn" :disabled="blockSaving">{{ blockSaving ? '提交中' : '提交封禁' }}</button>
        </form>
        <div class="block-group-title">目标 IP 地址封禁</div>
        <form class="block-form" @submit.prevent="addTargetIpBlockRule">
          <input v-model="targetIpKeyword" placeholder="输入目标 IP，例如 8.8.8.8" maxlength="128" />
          <button class="primary-btn" :disabled="blockSaving">{{ blockSaving ? '提交中' : '封禁目标 IP' }}</button>
        </form>
        <p v-if="blockError" class="form-message error-message">{{ blockError }}</p>
        <div v-if="domainBlockRules.length" class="block-list">
          <span v-for="rule in domainBlockRules" :key="rule.id" class="block-chip" :class="{ disabled: !rule.enabled }">
            <em>域名</em>
            <b>{{ rule.keyword }}</b>
            <button type="button" @click="toggleBlockRule(rule)">{{ rule.enabled ? '停用' : '启用' }}</button>
            <button type="button" @click="deleteBlockRule(rule)">删除</button>
          </span>
        </div>
        <div v-if="targetIpBlockRules.length" class="block-list">
          <span v-for="rule in targetIpBlockRules" :key="rule.id" class="block-chip ip-chip" :class="{ disabled: !rule.enabled }">
            <em>目标 IP</em>
            <b>{{ rule.keyword }}</b>
            <button type="button" @click="toggleBlockRule(rule)">{{ rule.enabled ? '停用' : '启用' }}</button>
            <button type="button" @click="deleteBlockRule(rule)">删除</button>
          </span>
        </div>
        <div v-if="!blockRules.length" class="empty-state compact">
          <strong>暂无封禁规则</strong>
          <span>域名命中 HTTP Host、TLS SNI 或 QUIC SNI 后阻断；目标 IP 命中远端地址后阻断。</span>
        </div>
      </section>

      <section class="panel forensic-panel">
        <div class="panel-head">
          <div>
            <p class="eyebrow">Forensics</p>
            <h3>端口取证</h3>
          </div>
          <span class="hint">{{ forensicsSessions.length }} 个任务</span>
        </div>
        <form class="forensic-form" @submit.prevent="startForensics">
          <select v-model.number="forensicsForm.listenPort">
            <option v-for="port in forensicPortOptions" :key="port" :value="port">{{ port }}</option>
          </select>
          <input v-model="forensicsForm.fileName" placeholder="文件名，例如 case-1080.txt" maxlength="160" />
          <input v-model.number="forensicsForm.durationMinutes" type="number" min="1" max="1440" />
          <button class="primary-btn" :disabled="forensicsSaving">{{ forensicsSaving ? '启动中' : '开始取证' }}</button>
        </form>
        <p v-if="forensicsError" class="form-message error-message">{{ forensicsError }}</p>
        <div v-if="forensicsSessions.length" class="forensic-list">
          <article v-for="session in forensicsSessions" :key="session.listenPort" class="forensic-item">
            <div>
              <strong>{{ session.listenPort }}</strong>
              <span>{{ session.fileName }}</span>
              <small>{{ session.filePath }}</small>
            </div>
            <button class="secondary-btn danger-btn" @click="stopForensics(session.listenPort)">停止</button>
          </article>
        </div>
        <div v-else class="empty-state compact">
          <strong>暂无取证任务</strong>
          <span>开启后会记录该端口的 TLS/QUIC SNI、Trojan 命中和 SS 命中，每条一行写入 txt。</span>
        </div>
      </section>

      <section class="content-grid">
        <article class="panel panel-wide">
          <div class="panel-head">
            <div>
              <p class="eyebrow">Clients</p>
              <h3>客户端访问概览</h3>
            </div>
            <span class="hint">点击客户端展开域名明细</span>
          </div>

          <div v-if="clients.length === 0" class="empty-state">
            <strong>暂无客户端数据</strong>
            <span>有流量经过后这里会自动出现访问摘要。</span>
          </div>

          <div v-else class="client-list">
            <div v-for="client in clients" :key="`${client.listenPort}-${client.ip}`" class="client-item">
              <button class="client-row" @click="toggleClient(client)">
                <span class="avatar">{{ getAvatar(client.ip) }}</span>
                <span class="port-badge">{{ client.listenPort }}</span>
                <span class="client-ip">{{ client.ip }}</span>
                <span class="client-count">{{ client.totalRequests }} 次请求</span>
                <span class="chevron">{{ client.open ? '收起' : '展开' }}</span>
              </button>

              <div v-show="client.open" class="client-domains">
                <table>
                  <thead>
                    <tr><th>#</th><th>域名</th><th>次数</th></tr>
                  </thead>
                  <tbody>
                    <tr v-for="(d, i) in client.topDomains" :key="`${client.listenPort}-${client.ip}-${d.protocol}-${d.domain}`">
                      <td>{{ i + 1 }}</td>
                      <td class="domain-cell">
                        <span class="sni-protocol" :class="protocolClass(d.protocol)">{{ d.protocol || 'TLS' }}</span>
                        {{ d.domain }}
                      </td>
                      <td class="count-cell">{{ d.count }}</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </article>

        <article class="panel">
          <div class="panel-head">
            <div>
              <p class="eyebrow">Tunnel</p>
              <h3>加密隧道触发排行</h3>
            </div>
          </div>
          <div class="table-wrap">
            <table>
              <thead>
                <tr><th>#</th><th>端口</th><th>客户端 IP</th><th>次数</th></tr>
              </thead>
              <tbody>
                <tr v-if="ssRanking.length === 0">
                  <td colspan="4" class="empty-td">暂无异常触发</td>
                </tr>
                <tr v-for="(r, i) in ssRanking" :key="`${r.listenPort}-${r.ip}`">
                  <td>{{ i + 1 }}</td>
                  <td><span class="port-badge">{{ r.listenPort }}</span></td>
                  <td class="ip-cell">{{ r.ip }}</td>
                  <td class="danger-text">{{ r.count }}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </article>

        <article class="panel">
          <div class="panel-head">
            <div>
              <p class="eyebrow">Domains</p>
              <h3>24 小时域名排行</h3>
            </div>
            <span class="hint">Top 30</span>
          </div>
          <div class="table-wrap">
            <table>
              <thead>
                <tr><th>#</th><th>域名</th><th>次数</th></tr>
              </thead>
              <tbody>
                <tr v-if="topSites.length === 0">
                  <td colspan="3" class="empty-td">暂无数据</td>
                </tr>
                <tr v-for="(s, i) in topSites" :key="`${s.protocol}-${s.domain}`">
                  <td>{{ i + 1 }}</td>
                  <td class="domain-cell">
                    <span class="sni-protocol" :class="protocolClass(s.protocol)">{{ s.protocol || 'TLS' }}</span>
                    {{ s.domain }}
                  </td>
                  <td class="count-cell">{{ s.count }}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </article>

        <article class="panel panel-full">
          <div class="panel-head">
            <div>
              <p class="eyebrow">Risk</p>
              <h3>高危加密目标</h3>
            </div>
            <span class="hint">{{ highRisk.length }} 个目标</span>
          </div>
          <div class="table-wrap">
            <table>
              <thead>
                <tr><th>#</th><th>端口</th><th>协议</th><th>目标 IP</th><th>触发次数</th><th>来源客户端</th></tr>
              </thead>
              <tbody>
                <tr v-if="highRisk.length === 0">
                  <td colspan="6" class="empty-td">暂无高危目标</td>
                </tr>
                <tr v-for="(r, i) in highRisk" :key="`${r.listenPort}-${r.protocol}-${r.ip}`">
                  <td>{{ i + 1 }}</td>
                  <td><span class="port-badge">{{ r.listenPort }}</span></td>
                  <td>
                    <span class="protocol-tag" :class="'protocol-' + String(r.protocol || 'SS').toLowerCase()">
                      {{ r.protocol || 'SS' }}
                    </span>
                  </td>
                  <td class="ip-cell danger-text">{{ r.ip }}</td>
                  <td class="danger-text">{{ r.count }}</td>
                  <td>
                    <span v-for="c in r.clients" :key="`${r.ip}-${c.ip}`" class="source-tag">
                      {{ c.ip }} · {{ c.count }}
                    </span>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </article>
      </section>
    </main>

    <div v-if="credentialDialogOpen" class="modal-backdrop" @click.self="closeCredentialDialog">
      <section class="modal" aria-label="修改用户名和密码">
        <div class="modal-head">
          <div>
            <p class="eyebrow">Account</p>
            <h3>修改登录信息</h3>
          </div>
          <button class="icon-btn" @click="closeCredentialDialog" aria-label="关闭">×</button>
        </div>

        <div class="modal-body">
          <label class="field">
            <span>原用户名</span>
            <input v-model="credentialForm.oldUsername" autocomplete="username" />
          </label>
          <label class="field">
            <span>原密码</span>
            <input v-model="credentialForm.oldPassword" type="password" autocomplete="current-password" />
          </label>
          <label class="field">
            <span>新用户名</span>
            <input v-model="credentialForm.newUsername" autocomplete="username" />
          </label>
          <label class="field">
            <span>新密码</span>
            <input v-model="credentialForm.newPassword" type="password" autocomplete="new-password" />
          </label>
          <label class="field">
            <span>确认新密码</span>
            <input v-model="credentialForm.confirmPassword" type="password" autocomplete="new-password" @keyup.enter="submitCredentials" />
          </label>

          <p v-if="credentialError" class="form-message error-message">{{ credentialError }}</p>
          <p v-if="credentialSuccess" class="form-message success-message">{{ credentialSuccess }}</p>
        </div>

        <div class="modal-actions">
          <button class="secondary-btn" @click="closeCredentialDialog">取消</button>
          <button class="primary-btn" :disabled="credentialSaving" @click="submitCredentials">
            {{ credentialSaving ? '保存中' : '保存修改' }}
          </button>
        </div>
      </section>
    </div>

    <div v-if="runtimeDialogOpen" class="modal-backdrop" @click.self="closeRuntimeDialog">
      <section class="modal wide-modal" aria-label="入站设置">
        <div class="modal-head">
          <div>
            <p class="eyebrow">Inbound</p>
            <h3>API 与 SOCKS5 入站</h3>
          </div>
          <button class="icon-btn" @click="closeRuntimeDialog" aria-label="关闭">×</button>
        </div>

        <div class="modal-body">
          <label class="field">
            <span>当前用户名</span>
            <input v-model="runtimeForm.oldUsername" autocomplete="username" />
          </label>
          <label class="field">
            <span>当前密码</span>
            <input v-model="runtimeForm.oldPassword" type="password" autocomplete="current-password" />
          </label>
          <label class="field">
            <span>API 监听端口</span>
            <input v-model.number="runtimeForm.api.port" type="number" min="1" max="65535" />
          </label>

          <div class="runtime-head">
            <strong>SOCKS5 入站</strong>
            <button type="button" class="secondary-btn" @click="addRuntimeInbound">添加入站</button>
          </div>
          <div v-for="(inbound, index) in runtimeForm.inbounds" :key="inbound.id || index" class="runtime-inbound">
            <div class="runtime-inbound-head">
              <strong>入站 {{ index + 1 }}</strong>
              <button v-if="runtimeForm.inbounds.length > 1" type="button" class="secondary-btn danger-btn" @click="removeRuntimeInbound(index)">删除</button>
            </div>
            <label class="field">
              <span>昵称</span>
              <input v-model="inbound.nickname" />
            </label>
            <label class="field">
              <span>监听端口</span>
              <input v-model.number="inbound.port" type="number" min="1" max="65535" />
            </label>
            <label class="toggle-row">
              <input v-model="inbound.enabled" type="checkbox" />
              <span>启用这个入站</span>
            </label>
            <label class="toggle-row">
              <input v-model="inbound.authEnabled" type="checkbox" />
              <span>启用 SOCKS5 用户名密码认证</span>
            </label>
            <template v-if="inbound.authEnabled">
              <label class="field">
                <span>SOCKS5 用户名</span>
                <input v-model="inbound.username" autocomplete="username" />
              </label>
              <label class="field">
                <span>SOCKS5 新密码</span>
                <input v-model="inbound.password" type="password" autocomplete="new-password" placeholder="留空则保持原密码" />
              </label>
            </template>
          </div>

          <p v-if="runtimeError" class="form-message error-message">{{ runtimeError }}</p>
          <p v-if="runtimeSuccess" class="form-message success-message">{{ runtimeSuccess }}</p>
        </div>

        <div class="modal-actions">
          <button class="secondary-btn" @click="closeRuntimeDialog">取消</button>
          <button class="primary-btn" :disabled="runtimeSaving" @click="submitRuntime">
            {{ runtimeSaving ? '保存中' : '保存配置' }}
          </button>
        </div>
      </section>
    </div>

    <div v-if="databaseDialogOpen" class="modal-backdrop" @click.self="closeDatabaseDialog">
      <section class="modal" aria-label="修改数据库配置">
        <div class="modal-head">
          <div>
            <p class="eyebrow">Database</p>
            <h3>数据库设置</h3>
          </div>
          <button class="icon-btn" @click="closeDatabaseDialog" aria-label="关闭">×</button>
        </div>

        <div class="modal-body">
          <div class="segment">
            <button :class="{ active: databaseForm.type === 'H2' }" @click="databaseForm.type = 'H2'">H2</button>
            <button :class="{ active: databaseForm.type === 'MYSQL' }" @click="databaseForm.type = 'MYSQL'">MySQL</button>
          </div>

          <label class="field">
            <span>当前用户名</span>
            <input v-model="databaseForm.oldUsername" autocomplete="username" />
          </label>
          <label class="field">
            <span>当前密码</span>
            <input v-model="databaseForm.oldPassword" type="password" autocomplete="current-password" />
          </label>

          <label v-if="databaseForm.type === 'H2'" class="field">
            <span>H2 数据路径</span>
            <input v-model="databaseForm.path" placeholder="./data/socks5_stats" />
          </label>

          <template v-else>
            <label class="field">
              <span>MySQL 地址</span>
              <input v-model="databaseForm.host" placeholder="127.0.0.1" />
            </label>
            <label class="field">
              <span>MySQL 端口</span>
              <input v-model.number="databaseForm.port" type="number" min="1" max="65535" />
            </label>
            <label class="field">
              <span>数据库名</span>
              <input v-model="databaseForm.databaseName" placeholder="qweovo_detect" />
            </label>
            <label class="field">
              <span>MySQL 用户名</span>
              <input v-model="databaseForm.username" autocomplete="username" />
            </label>
            <label class="field">
              <span>MySQL 密码</span>
              <input v-model="databaseForm.password" type="password" autocomplete="current-password" />
            </label>
          </template>

          <p v-if="databaseError" class="form-message error-message">{{ databaseError }}</p>
          <p v-if="databaseSuccess" class="form-message success-message">{{ databaseSuccess }}</p>
        </div>

        <div class="modal-actions">
          <button class="secondary-btn" @click="closeDatabaseDialog">取消</button>
          <button class="primary-btn" :disabled="databaseSaving" @click="submitDatabase">
            {{ databaseSaving ? '保存中' : '保存配置' }}
          </button>
        </div>
      </section>
    </div>
  </div>
</template>

<script setup>
import { computed, ref, onMounted, onUnmounted } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '../stores/auth'
import api from '../api'

const router = useRouter()
const authStore = useAuthStore()

const total = ref(0)
const sites = ref(0)
const clientCount = ref(0)
const ssTotal = ref(0)
const trojanTotal = ref(0)
const riskCount = ref(0)
const clients = ref([])
const topSites = ref([])
const ssRanking = ref([])
const highRisk = ref([])
const portSummary = ref([])
const blockRules = ref([])
const blockKeyword = ref('')
const targetIpKeyword = ref('')
const blockSaving = ref(false)
const blockError = ref('')
const forensicsSessions = ref([])
const forensicsSaving = ref(false)
const forensicsError = ref('')
const forensicsForm = ref({
  listenPort: 1080,
  fileName: 'forensics-1080.txt',
  durationMinutes: 5
})
const nowTime = ref('')
const credentialDialogOpen = ref(false)
const credentialSaving = ref(false)
const credentialError = ref('')
const credentialSuccess = ref('')
const databaseDialogOpen = ref(false)
const databaseSaving = ref(false)
const databaseError = ref('')
const databaseSuccess = ref('')
const runtimeDialogOpen = ref(false)
const runtimeSaving = ref(false)
const runtimeError = ref('')
const runtimeSuccess = ref('')
const credentialForm = ref({
  oldUsername: '',
  oldPassword: '',
  newUsername: '',
  newPassword: '',
  confirmPassword: ''
})
const databaseForm = ref({
  oldUsername: '',
  oldPassword: '',
  type: 'H2',
  path: './data/socks5_stats',
  host: '127.0.0.1',
  port: 3306,
  databaseName: '',
  username: '',
  password: ''
})
const runtimeForm = ref({
  oldUsername: '',
  oldPassword: '',
  api: {
    address: '127.0.0.1',
    port: 8080
  },
  inbounds: []
})
let timer = null

const avatarList = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J']

const metrics = computed(() => [
  { label: '监听端口', value: portSummary.value.length || 0, icon: 'PT', tone: 'tone-green' },
  { label: '客户端', value: clientCount.value, icon: 'CL', tone: 'tone-blue' },
  { label: 'TLS 记录', value: total.value, icon: 'TLS', tone: 'tone-blue' },
  { label: '活跃域名', value: sites.value, icon: 'DNS', tone: 'tone-cyan' },
  { label: '加密隧道', value: ssTotal.value, icon: 'ENC', tone: 'tone-amber' },
  { label: 'Trojan 命中', value: trojanTotal.value, icon: 'TR', tone: 'tone-red' },
  { label: '高危目标', value: riskCount.value, icon: 'HI', tone: 'tone-purple' }
])

const domainBlockRules = computed(() =>
  blockRules.value.filter(rule => String(rule.category || 'DOMAIN').toUpperCase() === 'DOMAIN')
)

const targetIpBlockRules = computed(() =>
  blockRules.value.filter(rule => String(rule.category || '').toUpperCase() === 'TARGET_IP')
)

const forensicPortOptions = computed(() => {
  const ports = portSummary.value.map(port => Number(port.listenPort)).filter(Boolean)
  return ports.length ? ports : [1080]
})

const greeting = computed(() => {
  const h = new Date().getHours()
  if (h < 6) return '夜间巡检中'
  if (h < 12) return '上午好，QWEOVO'
  if (h < 18) return '下午好，QWEOVO'
  return '晚上好，QWEOVO'
})

function getAvatar(ip) {
  let hash = 0
  for (let c of ip) hash += c.charCodeAt(0)
  return avatarList[hash % avatarList.length]
}

function toggleClient(client) {
  client.open = !client.open
}

function hasPortTraffic(port) {
  return Number(port.sniTotal || 0) > 0
    || Number(port.ssTotal || 0) > 0
    || Number(port.trojanTotal || 0) > 0
}

function protocolClass(protocol) {
  return String(protocol || 'TLS').toLowerCase() === 'quic' ? 'protocol-quic' : 'protocol-tls'
}

async function loadData() {
  try {
    const [totalRes, sitesRes, clientsRes, ssTotalRes, trojanTotalRes, ssRankRes, ssRiskRes, portsRes, blockRulesRes, forensicsRes] = await Promise.all([
      api.get('/total'),
      api.get('/top-sites', { params: { hours: 24 } }),
      api.get('/all-clients'),
      api.get('/ss/total'),
      api.get('/trojan/total'),
      api.get('/ss/client-ranking'),
      api.get('/ss/high-risk'),
      api.get('/ports/summary'),
      api.get('/block-rules'),
      api.get('/forensics')
    ])

    total.value = totalRes.data.total
    sites.value = sitesRes.data.length
    topSites.value = sitesRes.data
    clients.value = clientsRes.data.map(c => ({ ...c, open: false }))
    clientCount.value = clientsRes.data.length
    trojanTotal.value = trojanTotalRes.data.total
    ssTotal.value = ssTotalRes.data.total + trojanTotal.value
    ssRanking.value = ssRankRes.data
    highRisk.value = ssRiskRes.data
    riskCount.value = ssRiskRes.data.length
    portSummary.value = portsRes.data
    blockRules.value = blockRulesRes.data
    forensicsSessions.value = forensicsRes.data
    if (!forensicPortOptions.value.includes(forensicsForm.value.listenPort)) {
      forensicsForm.value.listenPort = forensicPortOptions.value[0]
    }
  } catch (e) {
    console.error('数据加载失败', e)
  }
}

async function loadForensics() {
  const res = await api.get('/forensics')
  forensicsSessions.value = res.data
}

async function loadBlockRules() {
  const res = await api.get('/block-rules')
  blockRules.value = res.data
}

async function addBlockRule() {
  blockError.value = ''
  const keyword = blockKeyword.value.trim()
  if (!keyword) {
    blockError.value = '请输入封禁关键词'
    return
  }

  blockSaving.value = true
  try {
    await api.post('/block-rules', { keyword })
    blockKeyword.value = ''
    await loadBlockRules()
  } catch (e) {
    blockError.value = e.response?.data?.message || '封禁规则提交失败'
  } finally {
    blockSaving.value = false
  }
}

async function addTargetIpBlockRule() {
  blockError.value = ''
  const ip = targetIpKeyword.value.trim()
  if (!ip) {
    blockError.value = '请输入要封禁的目标 IP 地址'
    return
  }

  blockSaving.value = true
  try {
    await api.post('/block-rules/target-ip', { ip })
    targetIpKeyword.value = ''
    await loadBlockRules()
  } catch (e) {
    blockError.value = e.response?.data?.message || '目标 IP 封禁规则提交失败'
  } finally {
    blockSaving.value = false
  }
}

async function toggleBlockRule(rule) {
  await api.post(`/block-rules/${rule.id}/enabled`, { enabled: !rule.enabled })
  await loadBlockRules()
}

async function deleteBlockRule(rule) {
  await api.delete(`/block-rules/${rule.id}`)
  await loadBlockRules()
}

async function startForensics() {
  forensicsError.value = ''
  if (!forensicsForm.value.fileName.trim()) {
    forensicsError.value = '请填写取证文件名'
    return
  }
  if (!forensicsForm.value.durationMinutes || forensicsForm.value.durationMinutes < 1) {
    forensicsError.value = '请填写取证时长'
    return
  }

  forensicsSaving.value = true
  try {
    await api.post('/forensics/start', {
      listenPort: Number(forensicsForm.value.listenPort),
      fileName: forensicsForm.value.fileName,
      durationMinutes: Number(forensicsForm.value.durationMinutes)
    })
    await loadForensics()
  } catch (e) {
    forensicsError.value = e.response?.data?.message || '启动取证失败'
  } finally {
    forensicsSaving.value = false
  }
}

async function stopForensics(listenPort) {
  await api.post(`/forensics/${listenPort}/stop`)
  await loadForensics()
}

function handleLogout() {
  authStore.logout()
  router.push('/login')
}

function openCredentialDialog() {
  credentialDialogOpen.value = true
  credentialError.value = ''
  credentialSuccess.value = ''
  credentialForm.value = {
    oldUsername: authStore.username || '',
    oldPassword: '',
    newUsername: authStore.username || '',
    newPassword: '',
    confirmPassword: ''
  }
}

function closeCredentialDialog() {
  if (credentialSaving.value) return
  credentialDialogOpen.value = false
}

async function openRuntimeDialog() {
  runtimeDialogOpen.value = true
  runtimeError.value = ''
  runtimeSuccess.value = ''
  runtimeForm.value.oldUsername = authStore.username || ''
  runtimeForm.value.oldPassword = ''
  try {
    const status = await authStore.setupStatus()
    applyRuntime(status)
  } catch (e) {
    runtimeError.value = '读取入站配置失败'
  }
}

function closeRuntimeDialog() {
  if (runtimeSaving.value) return
  runtimeDialogOpen.value = false
}

function newRuntimeInbound() {
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

function applyRuntime(status) {
  runtimeForm.value.api = {
    address: status.api?.address || '127.0.0.1',
    port: status.api?.port || 8080
  }
  runtimeForm.value.inbounds = Array.isArray(status.inbounds) && status.inbounds.length
    ? status.inbounds.map(inbound => ({
        id: inbound.id,
        nickname: inbound.nickname || `入站 ${inbound.port || 1080}`,
        port: inbound.port || 1080,
        enabled: inbound.enabled !== false,
        authEnabled: Boolean(inbound.authEnabled),
        username: inbound.username || '',
        password: ''
      }))
    : [newRuntimeInbound()]
}

function addRuntimeInbound() {
  runtimeForm.value.inbounds.push({
    ...newRuntimeInbound(),
    nickname: `入站 ${runtimeForm.value.inbounds.length + 1}`,
    port: 1080 + runtimeForm.value.inbounds.length
  })
}

function removeRuntimeInbound(index) {
  runtimeForm.value.inbounds.splice(index, 1)
}

async function submitRuntime() {
  runtimeError.value = ''
  runtimeSuccess.value = ''
  if (!runtimeForm.value.oldUsername || !runtimeForm.value.oldPassword) {
    runtimeError.value = '请填写当前用户名和当前密码'
    return
  }
  const error = validateRuntime()
  if (error) {
    runtimeError.value = error
    return
  }

  runtimeSaving.value = true
  try {
    const result = await authStore.saveRuntimeSetup({
      oldUsername: runtimeForm.value.oldUsername,
      oldPassword: runtimeForm.value.oldPassword,
      api: runtimeApiPayload(),
      inbounds: runtimeInboundPayload()
    })
    runtimeSuccess.value = result.requiresRestart ? '配置已保存，请重启后端服务生效。' : '配置已保存。'
    runtimeForm.value.oldPassword = ''
    runtimeForm.value.inbounds.forEach(inbound => { inbound.password = '' })
    await loadData()
  } catch (e) {
    runtimeError.value = e.response?.data?.error || '保存入站配置失败'
  } finally {
    runtimeSaving.value = false
  }
}

function validateRuntime() {
  const apiPort = Number(runtimeForm.value.api.port || 8080)
  if (apiPort < 1 || apiPort > 65535) return 'API 端口必须在 1-65535 之间'
  if (!runtimeForm.value.inbounds.some(inbound => inbound.enabled)) return '至少需要启用一个入站端口'
  const ports = new Set()
  for (const inbound of runtimeForm.value.inbounds) {
    const port = Number(inbound.port)
    if (port < 1 || port > 65535) return '入站端口必须在 1-65535 之间'
    if (ports.has(port)) return `入站端口不能重复：${port}`
    ports.add(port)
    if (inbound.enabled && port === apiPort) return 'API 端口不能和启用的入站端口相同'
    if (inbound.authEnabled && !inbound.username) return '启用 SOCKS5 认证时必须填写用户名'
  }
  return ''
}

function runtimeApiPayload() {
  return {
    address: runtimeForm.value.api.address || '127.0.0.1',
    port: Number(runtimeForm.value.api.port || 8080)
  }
}

function runtimeInboundPayload() {
  return runtimeForm.value.inbounds.map(inbound => ({
    id: inbound.id,
    nickname: inbound.nickname,
    port: Number(inbound.port),
    enabled: Boolean(inbound.enabled),
    authEnabled: Boolean(inbound.authEnabled),
    username: inbound.username,
    password: inbound.password
  }))
}

async function openDatabaseDialog() {
  databaseDialogOpen.value = true
  databaseError.value = ''
  databaseSuccess.value = ''
  databaseForm.value.oldUsername = authStore.username || ''
  databaseForm.value.oldPassword = ''
  try {
    const status = await authStore.setupStatus()
    applyDatabase(status.database)
  } catch (e) {
    databaseError.value = '读取数据库配置失败'
  }
}

function closeDatabaseDialog() {
  if (databaseSaving.value) return
  databaseDialogOpen.value = false
}

function applyDatabase(database) {
  if (!database) return
  databaseForm.value = {
    ...databaseForm.value,
    type: database.type || 'H2',
    path: database.path || './data/socks5_stats',
    host: database.host || '127.0.0.1',
    port: database.port || 3306,
    databaseName: database.databaseName || '',
    username: database.username || '',
    password: ''
  }
}

async function submitDatabase() {
  databaseError.value = ''
  databaseSuccess.value = ''

  const form = databaseForm.value
  if (!form.oldUsername || !form.oldPassword) {
    databaseError.value = '请填写当前用户名和当前密码'
    return
  }
  if (form.type === 'MYSQL' && (!form.databaseName || !form.username)) {
    databaseError.value = '请填写 MySQL 数据库名和用户名'
    return
  }

  databaseSaving.value = true
  try {
    const result = await authStore.saveDatabaseSetup({
      oldUsername: form.oldUsername,
      oldPassword: form.oldPassword,
      database: databasePayload()
    })
    databaseSuccess.value = result.requiresRestart
      ? '数据库配置已保存，请重启后端服务生效。'
      : '数据库配置已保存。'
    databaseForm.value.oldPassword = ''
    databaseForm.value.password = ''
  } catch (e) {
    databaseError.value = e.response?.data?.error || '保存数据库配置失败'
  } finally {
    databaseSaving.value = false
  }
}

function databasePayload() {
  if (databaseForm.value.type === 'H2') {
    return {
      type: 'H2',
      path: databaseForm.value.path
    }
  }

  return {
    type: 'MYSQL',
    host: databaseForm.value.host,
    port: Number(databaseForm.value.port || 3306),
    databaseName: databaseForm.value.databaseName,
    username: databaseForm.value.username,
    password: databaseForm.value.password
  }
}

async function submitCredentials() {
  credentialError.value = ''
  credentialSuccess.value = ''

  const form = credentialForm.value
  if (!form.oldUsername || !form.oldPassword || !form.newUsername || !form.newPassword) {
    credentialError.value = '请完整填写原用户名、原密码、新用户名和新密码'
    return
  }
  if (form.newPassword !== form.confirmPassword) {
    credentialError.value = '两次输入的新密码不一致'
    return
  }

  credentialSaving.value = true
  try {
    await authStore.changeCredentials({
      oldUsername: form.oldUsername,
      oldPassword: form.oldPassword,
      newUsername: form.newUsername,
      newPassword: form.newPassword
    })
    credentialSuccess.value = '登录信息已更新'
    credentialForm.value.oldPassword = ''
    credentialForm.value.newPassword = ''
    credentialForm.value.confirmPassword = ''
    setTimeout(() => {
      credentialDialogOpen.value = false
      credentialSuccess.value = ''
    }, 800)
  } catch (e) {
    credentialError.value = e.response?.data?.error || '修改失败，请检查原用户名和原密码'
  } finally {
    credentialSaving.value = false
  }
}

function updateTime() {
  nowTime.value = new Date().toLocaleString('zh-CN')
}

onMounted(() => {
  loadData()
  updateTime()
  timer = setInterval(() => {
    loadData()
    updateTime()
  }, 10000)
})

onUnmounted(() => {
  clearInterval(timer)
})
</script>

<style scoped>
.dashboard-shell {
  min-height: 100vh;
  background:
    linear-gradient(180deg, rgba(247, 250, 248, 0.94), rgba(241, 246, 244, 0.98)),
    radial-gradient(circle at 12% 8%, rgba(20, 184, 166, 0.14), transparent 26%),
    radial-gradient(circle at 96% 2%, rgba(245, 158, 11, 0.14), transparent 26%);
  color: #18231f;
}

.topbar {
  position: sticky;
  top: 0;
  z-index: 10;
  height: 72px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 28px;
  border-bottom: 1px solid rgba(22, 54, 48, 0.1);
  background: rgba(255, 255, 255, 0.82);
  backdrop-filter: blur(16px);
}

.brand,
.top-actions {
  display: flex;
  align-items: center;
}

.brand {
  gap: 12px;
}

.brand-mark {
  width: 42px;
  height: 42px;
  display: grid;
  place-items: center;
  border-radius: 8px;
  background: #15352f;
  color: #dcfff5;
  font-weight: 850;
}

.brand p,
.eyebrow {
  color: #58746d;
  font-size: 11px;
  font-weight: 850;
  letter-spacing: 0.12em;
  text-transform: uppercase;
}

.brand h1 {
  margin-top: 2px;
  color: #18231f;
  font-size: 18px;
  font-weight: 850;
}

.top-actions {
  gap: 12px;
  color: #536963;
  font-size: 13px;
}

.status-dot {
  width: 9px;
  height: 9px;
  border-radius: 50%;
  background: #10b981;
  box-shadow: 0 0 0 5px rgba(16, 185, 129, 0.14);
}

.user {
  padding: 6px 10px;
  border-radius: 999px;
  background: #edf5f2;
  color: #26443d;
  font-weight: 750;
}

.logout-btn {
  height: 34px;
  padding: 0 12px;
  border: 1px solid #cfddd8;
  border-radius: 8px;
  background: #ffffff;
  color: #24443d;
  cursor: pointer;
  font-weight: 750;
}

.secondary-btn,
.primary-btn,
.icon-btn {
  height: 34px;
  border-radius: 8px;
  cursor: pointer;
  font-weight: 750;
}

.secondary-btn {
  padding: 0 12px;
  border: 1px solid #cfddd8;
  background: #ffffff;
  color: #24443d;
}

.primary-btn {
  padding: 0 16px;
  border: 0;
  background: #15352f;
  color: #ffffff;
}

.primary-btn:disabled {
  cursor: wait;
  opacity: 0.72;
}

.icon-btn {
  width: 34px;
  border: 1px solid #cfddd8;
  background: #ffffff;
  color: #24443d;
  font-size: 20px;
  line-height: 1;
}

.dashboard-main {
  width: min(1480px, calc(100% - 48px));
  margin: 0 auto;
  padding: 30px 0 48px;
}

.intro {
  display: flex;
  align-items: flex-end;
  justify-content: space-between;
  gap: 24px;
  margin-bottom: 22px;
}

.intro h2 {
  margin-top: 6px;
  font-size: clamp(30px, 4vw, 46px);
  line-height: 1.1;
  font-weight: 880;
}

.intro-copy {
  max-width: 520px;
  color: #526963;
  line-height: 1.8;
}

.metrics-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 14px;
  margin-bottom: 18px;
}

.metric-card {
  min-height: 118px;
  display: flex;
  align-items: center;
  gap: 14px;
  padding: 18px;
  border: 1px solid rgba(31, 62, 55, 0.1);
  border-radius: 8px;
  background: #ffffff;
  box-shadow: 0 12px 34px rgba(24, 44, 38, 0.07);
}

.metric-icon {
  width: 42px;
  height: 42px;
  display: grid;
  place-items: center;
  border-radius: 8px;
  font-size: 12px;
  font-weight: 900;
}

.metric-card p {
  color: #647a74;
  font-size: 13px;
  font-weight: 760;
}

.metric-card strong {
  display: block;
  margin-top: 4px;
  color: #17211e;
  font-size: 30px;
  line-height: 1;
  font-weight: 900;
}

.tone-green .metric-icon { background: #def7ec; color: #047857; }
.tone-blue .metric-icon { background: #e3f2ff; color: #0369a1; }
.tone-cyan .metric-icon { background: #dff8f6; color: #0f766e; }
.tone-amber .metric-icon { background: #fff0cc; color: #b45309; }
.tone-red .metric-icon { background: #ffe4e6; color: #be123c; }
.tone-purple .metric-icon { background: #eee7ff; color: #6d28d9; }

.content-grid {
  display: grid;
  grid-template-columns: 1.25fr 1fr;
  gap: 18px;
}

.port-panel {
  margin-bottom: 18px;
}

.block-panel {
  margin-bottom: 18px;
  padding-bottom: 16px;
}

.block-form {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  gap: 10px;
  padding: 0 16px 12px;
}

.block-group-title {
  padding: 0 16px 8px;
  color: #47625b;
  font-size: 13px;
  font-weight: 850;
}

.block-form input {
  min-width: 0;
  height: 38px;
  padding: 0 12px;
  border: 1px solid #cfddd8;
  border-radius: 8px;
  background: #ffffff;
  color: #18332d;
  font-weight: 750;
}

.forensic-panel {
  margin-bottom: 18px;
  padding-bottom: 16px;
}

.forensic-form {
  display: grid;
  grid-template-columns: 120px minmax(0, 1fr) 110px auto;
  gap: 10px;
  padding: 0 16px 12px;
}

.forensic-form input,
.forensic-form select {
  min-width: 0;
  height: 38px;
  padding: 0 12px;
  border: 1px solid #cfddd8;
  border-radius: 8px;
  background: #ffffff;
  color: #18332d;
  font-weight: 750;
}

.forensic-list {
  display: grid;
  gap: 10px;
  padding: 0 16px;
}

.forensic-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 12px;
  border: 1px solid #dbe8e3;
  border-radius: 8px;
  background: #fbfefd;
}

.forensic-item div {
  min-width: 0;
  display: grid;
  gap: 3px;
}

.forensic-item span,
.forensic-item small {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.forensic-item small {
  color: #6b807a;
}

.block-list {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  padding: 0 16px;
}

.block-chip {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  min-height: 34px;
  padding: 5px 7px 5px 11px;
  border: 1px solid rgba(190, 18, 60, 0.18);
  border-radius: 8px;
  background: #fff1f2;
  color: #9f1239;
}

.block-chip em {
  padding: 3px 6px;
  border-radius: 5px;
  background: rgba(255, 255, 255, 0.86);
  font-style: normal;
  font-size: 11px;
  font-weight: 900;
}

.ip-chip {
  border-color: rgba(79, 70, 229, 0.18);
  background: #eef2ff;
  color: #4338ca;
}

.block-chip.disabled {
  border-color: #d9e5e0;
  background: #f4f8f6;
  color: #72867f;
}

.block-chip button {
  height: 24px;
  border: 0;
  border-radius: 6px;
  background: rgba(255, 255, 255, 0.8);
  color: inherit;
  cursor: pointer;
  font-weight: 800;
}

.port-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
  gap: 12px;
  padding: 16px;
}

.port-card {
  min-height: 130px;
  padding: 14px;
  border: 1px solid #e5eeea;
  border-radius: 8px;
  background: #fbfefd;
}

.port-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
}

.port-head strong {
  color: #15352f;
  font-size: 24px;
  font-weight: 900;
}

.port-head span {
  padding: 4px 8px;
  border-radius: 999px;
  background: #eef4f1;
  color: #70837e;
  font-size: 12px;
  font-weight: 800;
}

.port-head span.active {
  background: #def7ec;
  color: #047857;
}

.port-stats {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 8px;
  margin-top: 12px;
  color: #526963;
  font-size: 12px;
  font-weight: 750;
}

.port-domains {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  margin-top: 12px;
}

.port-domains span {
  max-width: 100%;
  padding: 4px 7px;
  border-radius: 7px;
  background: #eef8f5;
  color: #17614f;
  font-size: 12px;
  font-weight: 750;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.port-domains b,
.sni-protocol {
  display: inline-flex;
  align-items: center;
  height: 22px;
  margin-right: 7px;
  padding: 0 7px;
  border-radius: 6px;
  font-size: 11px;
  font-weight: 900;
}

.protocol-tls {
  background: #e3f2ff;
  color: #0369a1;
}

.protocol-quic {
  background: #eee7ff;
  color: #6d28d9;
}

.panel {
  min-width: 0;
  border: 1px solid rgba(31, 62, 55, 0.1);
  border-radius: 8px;
  background: rgba(255, 255, 255, 0.9);
  box-shadow: 0 14px 38px rgba(24, 44, 38, 0.07);
  overflow: hidden;
}

.panel-wide {
  grid-row: span 2;
}

.panel-full {
  grid-column: 1 / -1;
}

.panel-head {
  min-height: 74px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  padding: 18px 20px;
  border-bottom: 1px solid #e5eeea;
}

.panel-head h3 {
  margin-top: 4px;
  font-size: 17px;
  font-weight: 850;
}

.hint {
  color: #70837e;
  font-size: 12px;
}

.empty-state {
  display: grid;
  gap: 6px;
  padding: 34px 20px;
  color: #6b807a;
}

.empty-state strong {
  color: #29433d;
  font-size: 16px;
}

.empty-state.compact {
  margin: 0 16px;
  padding: 16px;
  border: 1px dashed #cfddd8;
  border-radius: 8px;
}

.client-list {
  display: grid;
}

.client-item + .client-item {
  border-top: 1px solid #edf3f0;
}

.client-row {
  width: 100%;
  display: grid;
  grid-template-columns: 38px auto minmax(150px, 1fr) auto auto;
  align-items: center;
  gap: 12px;
  padding: 14px 20px;
  border: 0;
  background: transparent;
  color: inherit;
  cursor: pointer;
  text-align: left;
}

.client-row:hover {
  background: #f6faf8;
}

.avatar {
  width: 34px;
  height: 34px;
  display: grid;
  place-items: center;
  border-radius: 8px;
  background: #e7f4ef;
  color: #17614f;
  font-weight: 900;
}

.port-badge {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: 54px;
  height: 26px;
  padding: 0 8px;
  border-radius: 7px;
  background: #eef4f1;
  color: #29433d;
  font-size: 12px;
  font-weight: 900;
}

.client-ip,
.ip-cell,
.domain-cell {
  color: #223730;
  font-weight: 760;
}

.client-count,
.chevron {
  color: #667b75;
  font-size: 13px;
  font-weight: 700;
}

.client-domains {
  padding: 0 20px 18px 70px;
}

.table-wrap {
  overflow-x: auto;
}

table {
  width: 100%;
  border-collapse: collapse;
}

th,
td {
  padding: 12px 16px;
  border-bottom: 1px solid #edf3f0;
  text-align: left;
  font-size: 13px;
  white-space: nowrap;
}

th {
  background: #f8fbfa;
  color: #70837e;
  font-size: 11px;
  font-weight: 850;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}

.count-cell {
  color: #0f766e;
  font-weight: 850;
}

.danger-text {
  color: #c2410c;
  font-weight: 880;
}

.empty-td {
  padding: 28px 16px;
  color: #70837e;
  text-align: center;
}

.protocol-tag,
.source-tag {
  display: inline-flex;
  align-items: center;
  min-height: 24px;
  padding: 3px 8px;
  border-radius: 7px;
  font-size: 12px;
  font-weight: 800;
}

.protocol-tag {
  min-width: 62px;
  justify-content: center;
  background: #eef4f1;
  color: #29433d;
}

.protocol-trojan {
  background: #ffe4e6;
  color: #be123c;
}

.protocol-ss {
  background: #fff0cc;
  color: #b45309;
}

.source-tag {
  margin: 2px 4px 2px 0;
  background: #eef8f5;
  color: #17614f;
}

.modal-backdrop {
  position: fixed;
  inset: 0;
  z-index: 30;
  display: grid;
  place-items: center;
  padding: 20px;
  background: rgba(12, 24, 21, 0.42);
  backdrop-filter: blur(8px);
}

.modal {
  width: min(460px, 100%);
  border: 1px solid rgba(31, 62, 55, 0.14);
  border-radius: 8px;
  background: #ffffff;
  box-shadow: 0 24px 80px rgba(11, 29, 24, 0.22);
  overflow: hidden;
}

.wide-modal {
  width: min(760px, 100%);
}

.modal-head,
.modal-actions {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 14px;
  padding: 18px 20px;
}

.modal-head {
  border-bottom: 1px solid #e5eeea;
}

.modal-head h3 {
  margin-top: 4px;
  font-size: 18px;
  font-weight: 850;
}

.modal-body {
  display: grid;
  gap: 14px;
  padding: 20px;
  max-height: min(72vh, 760px);
  overflow: auto;
}

.field {
  display: grid;
  gap: 7px;
}

.field span {
  color: #47625b;
  font-size: 13px;
  font-weight: 750;
}

.field input {
  width: 100%;
  height: 42px;
  padding: 0 12px;
  border: 1px solid #c9d8d3;
  border-radius: 8px;
  background: #fbfefd;
  color: #17211e;
  outline: none;
}

.field input:focus {
  border-color: #1f9f83;
  box-shadow: 0 0 0 4px rgba(31, 159, 131, 0.12);
}

.segment {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 8px;
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

.runtime-head,
.runtime-inbound-head,
.toggle-row {
  display: flex;
  align-items: center;
}

.runtime-head,
.runtime-inbound-head {
  justify-content: space-between;
  gap: 12px;
}

.runtime-inbound {
  display: grid;
  gap: 12px;
  padding: 14px;
  border: 1px solid #e1ece8;
  border-radius: 8px;
  background: #fbfefd;
}

.toggle-row {
  gap: 8px;
  color: #47625b;
  font-size: 13px;
  font-weight: 750;
}

.danger-btn {
  border-color: #fecdd3;
  color: #be123c;
}

.form-message {
  padding: 10px 12px;
  border-radius: 8px;
  font-size: 13px;
  font-weight: 750;
}

.error-message {
  background: #fff1f0;
  color: #b42318;
}

.success-message {
  background: #def7ec;
  color: #047857;
}

.modal-actions {
  justify-content: flex-end;
  border-top: 1px solid #e5eeea;
}

@media (max-width: 1180px) {
  .metrics-grid {
    grid-template-columns: repeat(3, minmax(0, 1fr));
  }

  .content-grid {
    grid-template-columns: 1fr;
  }

  .panel-wide {
    grid-row: auto;
  }
}

@media (max-width: 760px) {
  .topbar {
    height: auto;
    align-items: flex-start;
    flex-direction: column;
    gap: 14px;
    padding: 16px;
  }

  .top-actions {
    width: 100%;
    flex-wrap: wrap;
  }

  .dashboard-main {
    width: calc(100% - 28px);
    padding-top: 22px;
  }

  .intro {
    align-items: flex-start;
    flex-direction: column;
  }

  .metrics-grid {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .block-form {
    grid-template-columns: 1fr;
  }

  .forensic-form {
    grid-template-columns: 1fr;
  }

  .metric-card {
    min-height: 104px;
    padding: 14px;
  }

  .client-row {
    grid-template-columns: 36px auto 1fr;
  }

  .client-count,
  .chevron {
    grid-column: 3;
  }

  .client-domains {
    padding-left: 16px;
  }
}
</style>
