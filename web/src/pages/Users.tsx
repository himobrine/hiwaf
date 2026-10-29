import { useCallback, useEffect, useState } from 'react'
import {
  Alert,
  Button,
  Card,
  Form,
  Input,
  Modal,
  Popconfirm,
  Select,
  Space,
  Switch,
  Table,
  Tag,
  Tooltip,
  Typography,
  message,
} from 'antd'
import {
  DeleteOutlined,
  KeyOutlined,
  PlusOutlined,
  ReloadOutlined,
} from '@ant-design/icons'
import { api, fmtTs } from '../api'
import { generateStrongPassword, passwordError, PASSWORD_MIN_LEN } from '../password'
import type { User, UserRow } from '../types'

/** 与后端共用同一套强密码规则；用户名在密码里出现也会被拒。 */
function passwordRule(getUsername: () => string | undefined) {
  return {
    validator: async (_: any, value: string) => {
      const err = passwordError(value || '', getUsername())
      if (err) throw new Error(err)
    },
  }
}

function genButton(setValue: (v: string) => void) {
  return (
    <Button
      size="small"
      onClick={() => setValue(generateStrongPassword())}
      style={{ marginTop: 6 }}
    >
      生成强密码
    </Button>
  )
}

const { Title, Text } = Typography

const ROLE_OPTIONS = [
  { value: 'viewer', label: 'viewer · 只读' },
  { value: 'analyst', label: 'analyst · 分析 / 处置' },
  { value: 'admin', label: 'admin · 全部权限' },
]

const ROLE_COLOR: Record<string, string> = {
  viewer: 'default',
  analyst: 'blue',
  admin: 'red',
}

const ROLE_DESC: Record<string, string> = {
  viewer: '只读：看总览/事件/告警/规则证据',
  analyst: '可写：反馈、抑制、规则测试、数据预览',
  admin: '全部：规则/策略/模型/训练/采集代理/用户管理',
}

export default function Users({ user }: { user: User }) {
  const isAdmin = user.role === 'admin'
  const [items, setItems] = useState<UserRow[]>([])
  const [err, setErr] = useState('')
  const [loading, setLoading] = useState(false)
  const [busy, setBusy] = useState<string>('')

  const [createOpen, setCreateOpen] = useState(false)
  const [createForm] = Form.useForm()
  const [edit, setEdit] = useState<UserRow | null>(null)
  const [editForm] = Form.useForm()
  const [pwUser, setPwUser] = useState<UserRow | null>(null)
  const [pwForm] = Form.useForm()

  const load = useCallback(async () => {
    if (!isAdmin) return
    setLoading(true)
    setErr('')
    try {
      const r = await api<any>('/api/users')
      setItems(r.items || [])
    } catch (e: any) {
      setErr(e?.message || '加载失败')
    } finally {
      setLoading(false)
    }
  }, [isAdmin])

  useEffect(() => {
    load()
  }, [load])

  const create = async () => {
    let v: any
    try {
      v = await createForm.validateFields()
    } catch {
      return
    }
    setBusy('create')
    try {
      await api('/api/users', {
        method: 'POST',
        body: { username: v.username, password: v.password, role: v.role },
      })
      message.success(`已创建用户 ${v.username}`)
      setCreateOpen(false)
      createForm.resetFields()
      load()
    } catch (e: any) {
      message.error(e?.message || '创建失败')
    } finally {
      setBusy('')
    }
  }

  const openEdit = (r: UserRow) => {
    setEdit(r)
    editForm.setFieldsValue({ role: r.role, disabled: r.disabled })
  }

  const saveEdit = async () => {
    if (!edit) return
    let v: any
    try {
      v = await editForm.validateFields()
    } catch {
      return
    }
    setBusy(`edit-${edit.id}`)
    try {
      await api(`/api/users/${edit.id}`, {
        method: 'PATCH',
        body: { role: v.role, disabled: !!v.disabled },
      })
      message.success('已保存；该用户已签发的令牌会失效，需要重新登录')
      setEdit(null)
      load()
    } catch (e: any) {
      message.error(e?.message || '保存失败')
    } finally {
      setBusy('')
    }
  }

  const resetPassword = async () => {
    if (!pwUser) return
    let v: any
    try {
      v = await pwForm.validateFields()
    } catch {
      return
    }
    setBusy(`pw-${pwUser.id}`)
    try {
      await api(`/api/users/${pwUser.id}/password`, {
        method: 'POST',
        body: { password: v.password },
      })
      message.success('密码已重置；该用户需要重新登录')
      setPwUser(null)
      pwForm.resetFields()
    } catch (e: any) {
      message.error(e?.message || '重置失败')
    } finally {
      setBusy('')
    }
  }

  const remove = async (r: UserRow) => {
    setBusy(`del-${r.id}`)
    try {
      await api(`/api/users/${r.id}`, { method: 'DELETE' })
      message.success(`已删除用户 ${r.username}`)
      load()
    } catch (e: any) {
      message.error(e?.message || '删除失败')
    } finally {
      setBusy('')
    }
  }

  if (!isAdmin) {
    return (
      <div>
        <Title level={4} className="page-title">用户管理</Title>
        <Alert type="error" showIcon message="需要 admin 权限" />
      </div>
    )
  }

  return (
    <div>
      <div className="toolbar">
        <Title level={4} className="page-title">用户管理</Title>
        <Button icon={<ReloadOutlined />} onClick={load} loading={loading}>刷新</Button>
        <Button type="primary" icon={<PlusOutlined />} onClick={() => {
          createForm.resetFields()
          createForm.setFieldsValue({ role: 'analyst' })
          setCreateOpen(true)
        }}>
          新建用户
        </Button>
      </div>

      <Alert
        type="info"
        showIcon
        style={{ marginBottom: 12 }}
        message="安全约束"
        description={
          <span>
            至少保留一个<b>启用的 admin</b>；不能禁用/删除自己，也不能修改自己的角色；
            改密码 / 改角色 / 禁用会立刻让该用户已签发的令牌失效（需重新登录）。
            <br />
            <Text code>viewer</Text> 只读 · <Text code>analyst</Text> 可做反馈/抑制/规则测试 ·{' '}
            <Text code>admin</Text> 全部权限。
          </span>
        }
      />
      {err ? <Alert type="error" showIcon message={err} style={{ marginBottom: 12 }} /> : null}

      <Card size="small">
        <Table<UserRow>
          size="small"
          rowKey="id"
          loading={loading}
          dataSource={items}
          pagination={false}
          columns={[
            { title: 'ID', dataIndex: 'id', width: 70 },
            {
              title: '用户名',
              dataIndex: 'username',
              render: (v: string, r) => (
                <Space size={6}>
                  <Text code>{v}</Text>
                  {v === user.username ? <Tag color="green">当前用户</Tag> : null}
                  {r.disabled ? <Tag>已禁用</Tag> : null}
                </Space>
              ),
            },
            {
              title: '角色',
              dataIndex: 'role',
              width: 150,
              render: (v: string) => (
                <Tooltip title={ROLE_DESC[v] || ''}>
                  <Tag color={ROLE_COLOR[v] || 'default'}>{v}</Tag>
                </Tooltip>
              ),
            },
            {
              title: '状态',
              dataIndex: 'disabled',
              width: 100,
              render: (v: boolean) => (
                <Tag color={v ? 'default' : 'green'}>{v ? '禁用' : '启用'}</Tag>
              ),
            },
            { title: '创建时间', dataIndex: 'created_at', width: 170, render: (v: number) => fmtTs(v) },
            {
              title: '操作',
              width: 260,
              render: (_: any, r: UserRow) => {
                const self = r.username === user.username
                return (
                  <Space size={4} wrap>
                    <Button size="small" disabled={self} onClick={() => openEdit(r)}>编辑</Button>
                    <Button
                      size="small"
                      icon={<KeyOutlined />}
                      onClick={() => {
                        pwForm.resetFields()
                        setPwUser(r)
                      }}
                    >
                      重置密码
                    </Button>
                    {self ? (
                      <Tooltip title="不能删除自己">
                        <Button size="small" danger icon={<DeleteOutlined />} disabled />
                      </Tooltip>
                    ) : (
                      <Popconfirm
                        title={`删除用户 ${r.username}？`}
                        description="删除后不可恢复；该用户已签发的令牌立即失效。"
                        okText="删除"
                        okButtonProps={{ danger: true }}
                        onConfirm={() => remove(r)}
                      >
                        <Button
                          size="small"
                          danger
                          icon={<DeleteOutlined />}
                          loading={busy === `del-${r.id}`}
                        />
                      </Popconfirm>
                    )}
                  </Space>
                )
              },
            },
          ]}
        />
      </Card>

      <Modal
        open={createOpen}
        title="新建用户"
        okText="创建"
        confirmLoading={busy === 'create'}
        onCancel={() => setCreateOpen(false)}
        onOk={create}
        destroyOnClose
      >
        <Form form={createForm} layout="vertical" size="small">
          <Form.Item
            name="username"
            label="用户名"
            rules={[
              { required: true, message: '请输入用户名' },
              { pattern: /^[A-Za-z0-9_.-]{3,32}$/, message: '3–32 位字母/数字/下划线/点/短横线' },
            ]}
          >
            <Input autoComplete="off" placeholder="例如：analyst01" />
          </Form.Item>
          <Form.Item
            name="password"
            label="初始密码（强密码）"
            rules={[
              { required: true, message: '请输入初始密码' },
              passwordRule(() => createForm.getFieldValue('username')),
            ]}
            extra={
              <div>
                至少 {PASSWORD_MIN_LEN} 位，且同时包含大写、小写、数字和特殊字符；
                不能包含用户名 / 常见弱口令 / 连续序列。
                {genButton((v) => createForm.setFieldsValue({ password: v }))}
              </div>
            }
          >
            <Input.Password autoComplete="new-password" placeholder="点击下方「生成强密码」也可以" />
          </Form.Item>
          <Form.Item name="role" label="角色" rules={[{ required: true }]}>
            <Select options={ROLE_OPTIONS} />
          </Form.Item>
        </Form>
      </Modal>

      <Modal
        open={!!edit}
        title={edit ? `编辑用户 ${edit.username}` : ''}
        okText="保存"
        confirmLoading={busy.startsWith('edit-')}
        onCancel={() => setEdit(null)}
        onOk={saveEdit}
        destroyOnClose
      >
        {edit ? (
          <Form form={editForm} layout="vertical" size="small">
            <Form.Item name="role" label="角色" rules={[{ required: true }]}>
              <Select
                options={ROLE_OPTIONS}
                disabled={edit.username === user.username}
              />
            </Form.Item>
            <Form.Item
              name="disabled"
              label="禁用账号"
              valuePropName="checked"
              extra={edit.username === user.username ? '不能禁用自己' : '禁用后该用户立即无法登录'}
            >
              <Switch disabled={edit.username === user.username} />
            </Form.Item>
            <div className="muted">
              保存后该用户已签发的令牌会失效（需重新登录）。
            </div>
          </Form>
        ) : null}
      </Modal>

      <Modal
        open={!!pwUser}
        title={pwUser ? `重置密码：${pwUser.username}` : ''}
        okText="重置"
        confirmLoading={busy.startsWith('pw-')}
        onCancel={() => setPwUser(null)}
        onOk={resetPassword}
        destroyOnClose
      >
        <Alert
          type="warning"
          showIcon
          style={{ marginBottom: 12 }}
          message="重置后该用户已签发的令牌立即失效，需要用新密码重新登录。"
        />
        <Form form={pwForm} layout="vertical" size="small">
          <Form.Item
            name="password"
            label="新密码（强密码）"
            rules={[
              { required: true, message: '请输入新密码' },
              passwordRule(() => pwUser?.username),
            ]}
            extra={
              <div>
                至少 {PASSWORD_MIN_LEN} 位，且同时包含大写、小写、数字和特殊字符。
                {genButton((v) => pwForm.setFieldsValue({ password: v }))}
              </div>
            }
          >
            <Input.Password autoComplete="new-password" placeholder="至少 12 位" />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  )
}