import axios from 'axios'
import { useAuthStore } from '../stores/auth'

const api = axios.create({
  baseURL: '/api'
})

api.interceptors.request.use(config => {
  const authStore = useAuthStore()
  if (authStore.token) {
    config.headers.Authorization = `Bearer ${authStore.token}`
  }
  return config
})

api.interceptors.response.use(
  response => response,
  error => {
    const status = error.response?.status
    const url = error.config?.url || ''

    if ((status === 401 || status === 403) && !url.includes('/auth/login')) {
      const authStore = useAuthStore()
      authStore.logout()
      window.location.href = '/#/login'
    }

    return Promise.reject(error)
  }
)

export default api
