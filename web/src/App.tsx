import { lazy, Suspense, useEffect, useState } from 'react'
import { Navigate, Route, Routes } from 'react-router-dom'
import { Spin } from 'antd'
import { getToken, setToken } from './api'
import type { User } from './types'
import AppLayout from './components/AppLayout'
import Login from './pages/Login'

// 路由级懒加载：首屏只加载总览，模型页的 ECharts 等按需下载。
const Overview = lazy(() => import('./pages/Overview'))
const Events = lazy(() => import('./pages/Events'))
const Alerts = lazy(() => import('./pages/Alerts'))
const Suppressions = lazy(() => import('./pages/Suppressions'))
const Policy = lazy(() => import('./pages/Policy'))
const Feedback = lazy(() => import('./pages/Feedback'))
const Rules = lazy(() => import('./pages/Rules'))
const Models = lazy(() => import('./pages/Models'))
const Datasets = lazy(() => import('./pages/Datasets'))
const Tasks = lazy(() => import('./pages/Tasks'))
const Degradation = lazy(() => import('./pages/Degradation'))
const Audit = lazy(() => import('./pages/Audit'))

function loadUser(): User | null {
  try {
    const s = localStorage.getItem('waf_user')
    if (!s) return null
    if (!getToken()) return null
    return JSON.parse(s) as User
  } catch {
    return null
  }
}

export default function App() {
  const [user, setUser] = useState<User | null>(loadUser)

  useEffect(() => {
    const onUnauthorized = () => setUser(null)
    window.addEventListener('waf:unauthorized', onUnauthorized)
    return () => window.removeEventListener('waf:unauthorized', onUnauthorized)
  }, [])

  if (!user) {
    return (
      <Login
        onLogin={(u) => {
          localStorage.setItem('waf_user', JSON.stringify(u))
          setUser(u)
        }}
      />
    )
  }

  return (
    <AppLayout
      user={user}
      onLogout={() => {
        setToken('')
        localStorage.removeItem('waf_user')
        setUser(null)
      }}
    >
      <Suspense
        fallback={
          <div style={{ padding: 64, textAlign: 'center' }}>
            <Spin size="large" tip="加载页面…">
              <div style={{ height: 80 }} />
            </Spin>
          </div>
        }
      >
        <Routes>
          <Route path="/" element={<Overview />} />
          <Route path="/events" element={<Events user={user} />} />
          <Route path="/alerts" element={<Alerts user={user} />} />
          <Route path="/suppressions" element={<Suppressions user={user} />} />
          <Route path="/policy" element={<Policy user={user} />} />
          <Route path="/feedback" element={<Feedback user={user} />} />
          <Route path="/rules" element={<Rules user={user} />} />
          <Route path="/models" element={<Models user={user} />} />
          <Route path="/datasets" element={<Datasets user={user} />} />
          <Route path="/tasks" element={<Tasks user={user} />} />
          <Route path="/degradation" element={<Degradation />} />
          <Route path="/audit" element={<Audit />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </Suspense>
    </AppLayout>
  )
}
