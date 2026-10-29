import { useState } from 'react'
import { Alert, Button, Card, Form, Input, Modal, Typography, message } from 'antd'
import { api, setToken } from '../api'
import { generateStrongPassword, passwordError, PASSWORD_MIN_LEN } from '../password'
import type { User } from '../types'

const { Title, Text } = Typography

export default function Login({ onLogin }: { onLogin: (u: User) => void }) {
  const [loading, setLoading] = useState(false)
  const [err, setErr] = useState('')
  const [form] = Form.useForm()
  const [pwForm] = Form.useForm()
  const [pwBusy, setPwBusy] = useState(false)
  const [pwChange, setPwChange] = useState<{ user: User } | null>(null)

  const onFinish = async (v: any) => {
    setLoading(true)
    setErr('')
    try {
      const r = await api<{
        token: string
        user: User
        must_change_password?: boolean
      }>('/api/auth/login', {
        method: 'POST',
        body: v,
      })
      setToken(r.token)
      if (r.must_change_password) {
        // 密码不合规：先改密，改完必须用新密码重新登录。
        pwForm.resetFields()
        pwForm.setFieldsValue({ old: v.password })
        setPwChange({ user: r.user })
        return
      }
      onLogin(r.user)
    } catch (e: any) {
      setErr(e?.message || '登录失败')
    } finally {
      setLoading(false)
    }
  }

  const changeNow = async () => {
    let v: any
    try {
      v = await pwForm.validateFields()
    } catch {
      return
    }
    setPwBusy(true)
    try {
      await api('/api/auth/password', {
        method: 'POST',
        body: { old: v.old, new: v.new },
      })
      message.success('密码已修改，请用新密码重新登录')
      setToken('')
      setPwChange(null)
      pwForm.resetFields()
      form.setFieldsValue({ password: '' })
    } catch (e: any) {
      message.error(e?.message || '修改失败')
    } finally {
      setPwBusy(false)
    }
  }

  const abortChange = () => {
    setToken('')
    setPwChange(null)
    setErr('密码不符合强密码策略，必须先修改密码才能使用控制台')
  }

  return (
    <div className="login-wrap">
      <Card className="login-card">
        <Title level={3} className="login-title">
          WAF 控制台
        </Title>
        <div className="login-sub">AI 自动检测告警系统 · 安全运营业务台</div>
        {err ? <Alert type="error" message={err} style={{ marginBottom: 16 }} showIcon /> : null}
        <Form form={form} layout="vertical" onFinish={onFinish} initialValues={{ username: 'admin' }}>
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

      <Modal
        open={!!pwChange}
        title="必须先修改密码"
        okText="修改并重新登录"
        cancelText="取消"
        confirmLoading={pwBusy}
        onOk={changeNow}
        onCancel={abortChange}
        maskClosable={false}
        destroyOnClose
      >
        <Alert
          type="warning"
          showIcon
          style={{ marginBottom: 12 }}
          message="当前密码不符合强密码策略"
          description={
            <span>
              至少 {PASSWORD_MIN_LEN} 位，且同时包含大写、小写、数字和特殊字符；
              不能包含用户名 / 常见弱口令 / 连续序列。改完需要用新密码重新登录。
            </span>
          }
        />
        <Form form={pwForm} layout="vertical" size="small">
          <Form.Item name="old" label="原密码" rules={[{ required: true, message: '请输入原密码' }]}>
            <Input.Password autoComplete="current-password" />
          </Form.Item>
          <Form.Item
            name="new"
            label="新密码（强密码）"
            rules={[
              { required: true, message: '请输入新密码' },
              {
                validator: async (_: any, value: string) => {
                  const err = passwordError(value || '', pwChange?.user.username)
                  if (err) throw new Error(err)
                },
              },
            ]}
            extra={
              <div>
                至少 {PASSWORD_MIN_LEN} 位，含大写/小写/数字/特殊字符。
                <Button
                  size="small"
                  style={{ marginTop: 6 }}
                  onClick={() => pwForm.setFieldsValue({ new: generateStrongPassword() })}
                >
                  生成强密码
                </Button>
              </div>
            }
          >
            <Input.Password autoComplete="new-password" />
          </Form.Item>
          <Form.Item
            name="confirm"
            label="确认新密码"
            dependencies={['new']}
            rules={[
              { required: true, message: '请再次输入新密码' },
              {
                validator: async (_: any, value: string) => {
                  if (value !== pwForm.getFieldValue('new')) {
                    throw new Error('两次输入的密码不一致')
                  }
                },
              },
            ]}
          >
            <Input.Password autoComplete="new-password" />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  )
}
