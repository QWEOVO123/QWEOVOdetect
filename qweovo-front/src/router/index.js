import { createRouter, createWebHashHistory } from 'vue-router'
import { useAuthStore } from '../stores/auth'

const router = createRouter({
  history: createWebHashHistory(),
  routes: [
    {
      path: '/login',
      name: 'Login',
      component: () => import('../views/Login.vue')
    },
    {
      path: '/',
      name: 'Dashboard',
      component: () => import('../views/Dashboard.vue'),
      meta: { requiresAuth: true }
    },
    {
      path: '/:pathMatch(.*)*',
      redirect: '/'
    }
  ]
})

router.beforeEach(async (to, from, next) => {
  const authStore = useAuthStore()
  let setupLocked = false

  try {
    const setup = await authStore.setupStatus()
    setupLocked = Boolean(setup.firstStartup || setup.pendingRestart)
  } catch (e) {
    setupLocked = false
  }

  if (setupLocked) {
    if (to.path !== '/login') {
      next('/login')
      return
    }
    next()
    return
  }

  if (to.meta.requiresAuth && !authStore.isLoggedIn()) {
    next('/login')
    return
  }

  if (to.path === '/login' && authStore.isLoggedIn()) {
    next('/')
    return
  }

  next()
})

export default router
