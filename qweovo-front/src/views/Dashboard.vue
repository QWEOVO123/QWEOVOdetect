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
          <span class="hint">1080-1090 独立统计</span>
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
              <span v-for="domain in port.topDomains" :key="`${port.listenPort}-${domain.domain}`">
                {{ domain.domain }} · {{ domain.count }}
              </span>
            </div>
          </article>
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
                    <tr v-for="(d, i) in client.topDomains" :key="`${client.ip}-${d.domain}`">
                      <td>{{ i + 1 }}</td>
                      <td class="domain-cell">{{ d.domain }}</td>
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
                <tr v-for="(s, i) in topSites" :key="s.domain">
                  <td>{{ i + 1 }}</td>
                  <td class="domain-cell">{{ s.domain }}</td>
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
const nowTime = ref('')
let timer = null

const avatarList = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J']

const metrics = computed(() => [
  { label: '监听端口', value: portSummary.value.length || 11, icon: 'PT', tone: 'tone-green' },
  { label: '客户端', value: clientCount.value, icon: 'CL', tone: 'tone-blue' },
  { label: 'TLS 记录', value: total.value, icon: 'TLS', tone: 'tone-blue' },
  { label: '活跃域名', value: sites.value, icon: 'DNS', tone: 'tone-cyan' },
  { label: '加密隧道', value: ssTotal.value, icon: 'ENC', tone: 'tone-amber' },
  { label: 'Trojan 命中', value: trojanTotal.value, icon: 'TR', tone: 'tone-red' },
  { label: '高危目标', value: riskCount.value, icon: 'HI', tone: 'tone-purple' }
])

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

async function loadData() {
  try {
    const [totalRes, sitesRes, clientsRes, ssTotalRes, trojanTotalRes, ssRankRes, ssRiskRes, portsRes] = await Promise.all([
      api.get('/total'),
      api.get('/top-sites', { params: { hours: 24 } }),
      api.get('/all-clients'),
      api.get('/ss/total'),
      api.get('/trojan/total'),
      api.get('/ss/client-ranking'),
      api.get('/ss/high-risk'),
      api.get('/ports/summary')
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
  } catch (e) {
    console.error('数据加载失败', e)
  }
}

function handleLogout() {
  authStore.logout()
  router.push('/login')
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
