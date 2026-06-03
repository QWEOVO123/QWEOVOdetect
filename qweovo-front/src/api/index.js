import axios from 'axios'
import { useAuthStore } from '../stores/auth'

const api = axios.create({
  baseURL: '/api'
})

api.interceptors.request.use(config => {
  const authStore = useAuthStore()
  if (authStore.token) {
    config.headers.Authorization = `Bearer ${authStore.token}`
    config.authToken = authStore.token
  }
  return config
})

api.interceptors.response.use(
  response => response,
  error => {
    const status = error.response?.status
    const url = error.config?.url || ''
    const responseError = error.response?.data?.error
    const requestToken = error.config?.authToken

    const isAuthFailure = status === 401 || (status === 403 && !responseError)

    if (isAuthFailure && requestToken && !url.includes('/auth/login')) {
      const authStore = useAuthStore()
      if (requestToken === authStore.token) {
        authStore.logout()
        if (window.location.hash !== '#/login') {
          window.location.href = '/#/login'
        }
      }
    }

    return Promise.reject(error)
  }
)

export default api
