import { defineStore } from 'pinia'
import { ref } from 'vue'
import api from '../api'

export const useAuthStore = defineStore('auth', () => {
  const token = ref(localStorage.getItem('token') || '')
  const username = ref(localStorage.getItem('username') || '')

  // 登录
  async function login(form) {
    const res = await api.post('/auth/login', form)
    setSession(res.data.token, res.data.username)
  }

  async function changeCredentials(form) {
    const res = await api.post('/auth/credentials', form)
    setSession(res.data.token, res.data.username)
  }

  async function setupStatus() {
    const res = await api.get('/setup/status')
    return res.data
  }

  async function saveDatabaseSetup(form) {
    const res = await api.post('/setup/database', form)
    return res.data
  }

  function setSession(nextToken, nextUsername) {
    token.value = nextToken
    username.value = nextUsername
    localStorage.setItem('token', nextToken)
    localStorage.setItem('username', nextUsername)
  }

  async function refreshMe() {
    const res = await api.get('/auth/me')
    username.value = res.data.username
    localStorage.setItem('username', res.data.username)
  }

  // 登出
  function logout() {
    token.value = ''
    username.value = ''
    localStorage.removeItem('token')
    localStorage.removeItem('username')
  }

  // 是否已登录
  const isLoggedIn = () => !!token.value

  return {
    token,
    username,
    login,
    changeCredentials,
    setupStatus,
    saveDatabaseSetup,
    refreshMe,
    logout,
    isLoggedIn
  }
})
