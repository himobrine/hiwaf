import { useState } from 'react'
import { Alert, Button, Card, Form, Input, Typography } from 'antd'
import { api, setToken } from '../api'
import type { User } from '../types'

const { Title, Text } = Typography

export default function Login({ onLogin }: { onLogin: (u: User) => void }) {
  const [loading, setLoading] = useState(false)
  const [err, setErr] = useState('')

  const onFinish = async (v: any) => {
    setLoading(true)
    setErr('')
    try {
      const r = await api<{ token: string; user: User }>('/api/auth/login', {
        method: 'POST',
        body: v,
      })
      setToken(r.token)
      onLogin(r.user)
    } catch (e: any) {
      setErr(e?.message || '登录失败')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="login-wrap">
      <Card className="login-card">
        <Title level={3} className="login-title">
          WAF 控制台
        </Title>
        <div className="login-sub">AI 自动检测告警系统 · 安全运营业务台</div>
        {err ? <Alert type="error" message={err} style={{ marginBottom: 16 }} showIcon /> : null}
        <Form layout="vertical" onFinish={onFinish} initialValues={{ username: 'admin' }}>
          <Form.Item name="username" label="用户名" rules={[{ required: true }]}>
            <Input autoComplete="username" />
          </Form.Item>
          <Form.Item name="password" label="密码" rules={[{ required: true }]}>
            <Input.Password autoComplete="current-password" />
          </Form.Item>
          <Button type="primary" htmlType="submit" block loading={loading}>
            登录
          </Button>
        </Form>
        <div className="muted" style={{ marginTop: 16, textAlign: 'center' }}>
          首次启动的初始密码见 <Text code>python/service/.admin_password</Text>
          <br />
          登录后请立即修改密码。
        </div>
      </Card>
    </div>
  )
}
