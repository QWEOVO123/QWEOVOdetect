<template>
  <div class="dashboard">
    <!-- 顶部栏 -->
    <div class="header">
      <div class="header-left">
        <span class="logo-icon">🍞</span>
        <h1>QWEOVO 小面包检测站</h1>
        <span class="version">v1.0.2</span>
      </div>
      <div class="header-right">
        <span class="greeting">{{ greeting }}</span>
        <span class="user">👤 {{ authStore.username }}</span>
        <button class="logout-btn" @click="handleLogout">出门</button>
      </div>
    </div>

    <!-- 统计卡片 -->
    <div class="stats">
      <div class="card card-yellow">
        <div class="card-icon">🖥️</div>
        <div class="card-info">
          <h2>客户端数量</h2>
          <div class="num">{{ clientCount }}</div>
        </div>
      </div>
      <div class="card card-cream">
        <div class="card-icon">🔒</div>
        <div class="card-info">
          <h2>TLS 检测次数</h2>
          <div class="num">{{ total }}</div>
        </div>
      </div>
      <div class="card card-peach">
        <div class="card-icon">🌐</div>
        <div class="card-info">
          <h2>活跃域名</h2>
          <div class="num">{{ sites }}</div>
        </div>
      </div>
      <div class="card card-brown">
        <div class="card-icon">🚨</div>
        <div class="card-info">
          <h2>加密隧道</h2>
          <div class="num num-alert">{{ ssTotal }}</div>
        </div>
      </div>
      <div class="card card-orange">
        <div class="card-icon">⚠️</div>
        <div class="card-info">
          <h2>高危 IP</h2>
          <div class="num num-alert">{{ riskCount }}</div>
        </div>
      </div>
    </div>

    <!-- 客户端 SNI 概览 -->
    <div class="section">
      <div class="section-title">
        <span>🐱 客户端小本本</span>
        <span class="section-hint">点击展开查看详情</span>
      </div>
      <div v-if="clients.length === 0" class="empty">
        <span class="empty-icon">🍃</span>
        <p>还没有客户端数据呢~</p>
      </div>
      <div v-for="client in clients" :key="client.ip" class="client-block">
        <div class="client-header" @click="toggleClient(client)">
          <div class="client-left">
            <span class="client-avatar">{{ getAvatar(client.ip) }}</span>
            <span class="client-ip">{{ client.ip }}</span>
          </div>
          <div class="client-right">
            <span class="client-total">📋 {{ client.totalRequests }} 次请求</span>
            <span class="expand-icon">{{ client.open ? '🔼' : '🔽' }}</span>
          </div>
        </div>
        <div v-show="client.open" class="client-body">
          <table>
            <thead>
              <tr><th>#</th><th>域名</th><th>次数</th></tr>
            </thead>
            <tbody>
              <tr v-for="(d, i) in client.topDomains" :key="i">
                <td class="rank-cell">{{ i + 1 }}</td>
                <td class="domain-cell">🔗 {{ d.domain }}</td>
                <td class="count-cell">{{ d.count }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- SS 客户端排行 -->
    <div class="section">
      <div class="section-title section-title-alert">
        <span>🚨 加密隧道触发排行</span>
      </div>
      <table class="simple-table">
        <thead>
          <tr><th>#</th><th>客户端 IP</th><th>触发次数</th></tr>
        </thead>
        <tbody>
          <tr v-if="ssRanking.length === 0"><td colspan="3" class="empty-td">🍀 太棒了，没有异常！</td></tr>
          <tr v-for="(r, i) in ssRanking" :key="i">
            <td class="rank-cell">{{ i + 1 }}</td>
            <td class="ip-cell">🖥️ {{ r.ip }}</td>
            <td class="count-cell count-alert">{{ r.count }}</td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- 高危目标 -->
    <div class="section">
      <div class="section-title section-title-alert">
        <span>⚠️ 高危加密地址</span>
      </div>
      <table class="simple-table">
        <thead>
          <tr><th>#</th><th>协议</th><th>目标 IP</th><th>触发次数</th><th>来源客户端</th></tr>
        </thead>
        <tbody>
          <tr v-if="highRisk.length === 0"><td colspan="5" class="empty-td">🍀 没有高危地址，安心~</td></tr>
          <tr v-for="(r, i) in highRisk" :key="i">
            <td class="rank-cell">{{ i + 1 }}</td>
            <td><span class="protocol-tag" :class="'protocol-' + String(r.protocol || 'SS').toLowerCase()">{{ r.protocol || 'SS' }}</span></td>
            <td class="ip-cell ip-danger">💀 {{ r.ip }}</td>
            <td class="count-cell count-alert">{{ r.count }}</td>
            <td>
              <span v-for="c in r.clients" :key="c.ip" class="source-tag">
                {{ c.ip }} ({{ c.count }})
              </span>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- 24小时域名排行 -->
    <div class="section">
      <div class="section-title">
        <span>🏆 24小时域名访问排行</span>
        <span class="section-hint">Top 30</span>
      </div>
      <table class="simple-table">
        <thead>
          <tr><th>#</th><th>域名</th><th>访问次数</th></tr>
        </thead>
        <tbody>
          <tr v-if="topSites.length === 0"><td colspan="3" class="empty-td">🌙 暂无数据</td></tr>
          <tr v-for="(s, i) in topSites" :key="i">
            <td class="rank-cell">
              <span v-if="i === 0">🥇</span>
              <span v-else-if="i === 1">🥈</span>
              <span v-else-if="i === 2">🥉</span>
              <span v-else>{{ i + 1 }}</span>
            </td>
            <td class="domain-cell">🔗 {{ s.domain }}</td>
            <td class="count-cell">{{ s.count }}</td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- 底部 -->
    <div class="footer">
      <p>🍞 QWEOVO 小面包检测站 · 用心守护每一包流量 · {{ nowTime }}</p>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted } from 'vue'
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
const nowTime = ref('')
let timer = null

// 随机头像
const avatarList = ['🐱', '🐶', '🐰', '🐻', '🐼', '🐨', '🦊', '🐯', '🐸', '🐵', '🐣', '🦄']
function getAvatar(ip) {
  let hash = 0
  for (let c of ip) hash += c.charCodeAt(0)
  return avatarList[hash % avatarList.length]
}

// 根据时间问候
const greeting = computed(() => {
  const h = new Date().getHours()
  if (h < 6) return '🌙 夜深了~'
  if (h < 9) return '🌅 早上好~'
  if (h < 12) return '☀️ 上午好~'
  if (h < 14) return '🍱 中午好~'
  if (h < 18) return '🍵 下午好~'
  return '🌆 晚上好~'
})

function toggleClient(client) {
  client.open = !client.open
}

async function loadData() {
  try {
    const [totalRes, sitesRes, clientsRes, ssTotalRes, trojanTotalRes, ssRankRes, ssRiskRes] = await Promise.all([
      api.get('/total'),
      api.get('/top-sites', { params: { hours: 24 } }),
      api.get('/all-clients'),
      api.get('/ss/total'),
      api.get('/trojan/total'),
      api.get('/ss/client-ranking'),
      api.get('/ss/high-risk')
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
  } catch (e) {
    console.error('哎呀，数据加载失败了~', e)
  }
}

function handleLogout() {
  authStore.logout()
  router.push('/login')
}

function updateTime() {
  nowTime.value = new Date().toLocaleString('zh-CN')
}

import { computed } from 'vue'

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
/* ===== 全局 ===== */
.dashboard {
  min-height: 100vh;
  background: linear-gradient(180deg, #fff8e7 0%, #fef5e7 50%, #fdf2e0 100%);
  background-attachment: fixed;
  font-family: 'Segoe UI', 'PingFang SC', 'Microsoft YaHei', sans-serif;
  color: #5d4037;
}

/* ===== 顶部栏 ===== */
.header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 16px 32px;
  background: #fffdf5;
  border-bottom: 2px solid #e8d5b7;
  box-shadow: 0 2px 12px rgba(139, 90, 43, 0.06);
  position: sticky;
  top: 0;
  z-index: 100;
}
.header-left {
  display: flex;
  align-items: center;
  gap: 12px;
}
.logo-icon {
  font-size: 32px;
}
.header-left h1 {
  font-size: 20px;
  font-weight: 700;
  color: #6d4c41;
  letter-spacing: 1px;
}
.version {
  background: #ffe0b2;
  color: #bf6d3d;
  padding: 2px 10px;
  border-radius: 12px;
  font-size: 12px;
  font-weight: 600;
}
.header-right {
  display: flex;
  align-items: center;
  gap: 16px;
}
.greeting {
  color: #a1887f;
  font-size: 14px;
}
.user {
  color: #795548;
  font-weight: 600;
  font-size: 14px;
}
.logout-btn {
  background: #efebe9;
  color: #6d4c41;
  border: 1px solid #d7ccc8;
  padding: 6px 16px;
  border-radius: 20px;
  cursor: pointer;
  font-size: 13px;
  transition: all 0.2s;
}
.logout-btn:hover {
  background: #d7ccc8;
  border-color: #bcaaa4;
}

/* ===== 统计卡片 ===== */
.stats {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 16px;
  padding: 24px 32px;
}
.card {
  display: flex;
  align-items: center;
  gap: 16px;
  padding: 20px 24px;
  border-radius: 16px;
  border: 1px solid;
  transition: transform 0.2s, box-shadow 0.2s;
}
.card:hover {
  transform: translateY(-3px);
  box-shadow: 0 8px 24px rgba(139, 90, 43, 0.1);
}
.card-yellow {
  background: #fffde7;
  border-color: #ffe082;
}
.card-cream {
  background: #fff8e1;
  border-color: #ffcc80;
}
.card-peach {
  background: #fff3e0;
  border-color: #ffcc80;
}
.card-brown {
  background: #fff8f0;
  border-color: #ffab91;
}
.card-orange {
  background: #fff3ed;
  border-color: #ff8a65;
}
.card-icon {
  font-size: 36px;
  line-height: 1;
}
.card-info h2 {
  font-size: 12px;
  color: #8d6e63;
  margin-bottom: 4px;
  font-weight: 500;
}
.num {
  font-size: 30px;
  font-weight: 800;
  color: #5d4037;
}
.num-alert {
  color: #d84315;
}

/* ===== 分区 ===== */
.section {
  margin: 0 32px 24px;
  background: #fffdf7;
  border-radius: 16px;
  border: 1px solid #e8d5c4;
  overflow: hidden;
}
.section-title {
  padding: 16px 20px;
  font-size: 16px;
  font-weight: 700;
  color: #6d4c41;
  background: #fef9f0;
  border-bottom: 1px solid #e8d5c4;
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.section-title-alert {
  background: #fff5f0;
  color: #bf360c;
}
.section-hint {
  font-size: 12px;
  color: #a1887f;
  font-weight: 400;
}

/* ===== 客户端块 ===== */
.empty {
  text-align: center;
  padding: 40px;
  color: #a1887f;
}
.empty-icon {
  font-size: 40px;
  display: block;
  margin-bottom: 8px;
}
.client-block {
  border-bottom: 1px solid #efebe9;
}
.client-block:last-child {
  border-bottom: none;
}
.client-header {
  padding: 14px 20px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  cursor: pointer;
  transition: background 0.15s;
}
.client-header:hover {
  background: #fffdf5;
}
.client-left {
  display: flex;
  align-items: center;
  gap: 10px;
}
.client-avatar {
  font-size: 24px;
}
.client-ip {
  color: #5d4037;
  font-weight: 700;
  font-size: 15px;
}
.client-right {
  display: flex;
  align-items: center;
  gap: 12px;
}
.client-total {
  color: #8d6e63;
  font-size: 13px;
}
.expand-icon {
  font-size: 12px;
}
.client-body {
  padding: 8px 20px 16px;
  background: #fffef9;
}

/* ===== 表格 ===== */
.simple-table {
  width: 100%;
  border-collapse: collapse;
}
th, td {
  padding: 10px 16px;
  text-align: left;
  font-size: 14px;
}
th {
  background: #fef9f0;
  color: #8d6e63;
  font-weight: 600;
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  border-bottom: 2px solid #e8d5c4;
}
td {
  border-bottom: 1px solid #f5ebe0;
}
.rank-cell {
  color: #a1887f;
  font-weight: 600;
  width: 50px;
}
.domain-cell {
  color: #5d4037;
  font-weight: 500;
}
.count-cell {
  color: #bf6d3d;
  font-weight: 700;
}
.count-alert {
  color: #d84315;
}
.ip-cell {
  color: #5d4037;
  font-weight: 600;
}
.ip-danger {
  color: #bf360c;
  font-weight: 700;
}
.empty-td {
  text-align: center;
  color: #a1887f;
  padding: 24px;
  font-size: 14px;
}
.source-tag {
  display: inline-block;
  background: #fef0e6;
  color: #8d6e63;
  padding: 2px 10px;
  border-radius: 10px;
  font-size: 12px;
  margin: 2px 4px;
  border: 1px solid #f0dcc8;
}
.protocol-tag {
  display: inline-block;
  min-width: 58px;
  padding: 2px 8px;
  border-radius: 8px;
  font-size: 12px;
  font-weight: 700;
  text-align: center;
  background: #efebe9;
  color: #6d4c41;
  border: 1px solid #d7ccc8;
}
.protocol-trojan {
  background: #ffebee;
  color: #b71c1c;
  border-color: #ffcdd2;
}
.protocol-ss {
  background: #fff3e0;
  color: #bf360c;
  border-color: #ffccbc;
}

/* ===== 底部 ===== */
.footer {
  text-align: center;
  padding: 24px;
  color: #bcaaa4;
  font-size: 13px;
}
</style>
