import { useEffect, useState } from 'react'
import { Navigate, Route, Routes } from 'react-router-dom'
import { getToken, setToken } from './api'
import type { User } from './types'
import AppLayout from './components/AppLayout'
import Login from './pages/Login'
import Overview from './pages/Overview'
import Events from './pages/Events'
import Alerts from './pages/Alerts'
import Policy from './pages/Policy'
import Feedback from './pages/Feedback'
import Rules from './pages/Rules'
import Models from './pages/Models'
import Datasets from './pages/Datasets'
import Tasks from './pages/Tasks'
import Degradation from './pages/Degradation'
import Audit from './pages/Audit'

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
      <Routes>
        <Route path="/" element={<Overview />} />
        <Route path="/events" element={<Events user={user} />} />
        <Route path="/alerts" element={<Alerts user={user} />} />
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
    </AppLayout>
  )
}
