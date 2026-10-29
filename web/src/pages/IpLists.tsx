import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  Alert,
  Button,
  Card,
  Descriptions,
  Form,
  Input,
  InputNumber,
  Modal,
  Popconfirm,
  Space,
  Switch,
  Table,
  Tabs,
  Tag,
  Typography,
  message,
} from 'antd'
import {
  DeleteOutlined,
  DownloadOutlined,
  PlusOutlined,
  ReloadOutlined,
  UploadOutlined,
} from '@ant-design/icons'
import { api, download, fmtTs } from '../api'
import type { IpAutoSettings, IpListRow, User } from '../types'

const { Title, Text } = Typography

const KIND_LABEL: Record<string, string> = { black: '黑名单', white: '白名单' }
const KIND_COLOR: Record<string, string> = { black: 'red', white: 'green' }

export default function IpLists({ user }: { user: User }) {
  const canWrite = user.role !== 'viewer'
  const isAdmin = user.role === 'admin'
  const [kind, setKind] = useState<'black' | 'white'>('black')
  const [items, setItems] = useState<IpListRow[]>([])
  const [counts, setCounts] = useState<Record<string, number>>({})
  const [artifact, setArtifact] = useState<any>(null)
  const [settings, setSettings] = useState<IpAutoSettings | null>(null)
  const [loading, setLoading] = useState(false)
  const [err, setErr] = useState('')
  const [selected, setSelected] = useState<number[]>([])
  const [busy, setBusy] = useState('')

  const [addOpen, setAddOpen] = useState(false)
  const [addForm] = Form.useForm()
  const [importOpen, setImportOpen] = useState(false)
  const [importText, setImportText] = useState('')
  const [importForm] = Form.useForm()

  const load = useCallback(async () => {
    setLoading(true)
    setErr('')
    try {
      const r = await api<any>(`/api/ip-lists?kind=${kind}&limit=2000`)
      setItems(r.items || [])
      setCounts(r.counts || {})
      setArtifact(r.artifact || null)
      setSettings(r.settings || null)
      setSelected([])
    } catch (e: any) {
      setErr(e?.message || '加载失败')
    } finally {
      setLoading(false)
    }
  }, [kind])

  useEffect(() => {
    load()
  }, [load])

  const add = async () => {
    let v: any
    try {
      v = await addForm.validateFields()
    } catch {
      return
    }
    setBusy('add')
    try {
      await api('/api/ip-lists', {
        method: 'POST',
        body: { ip: v.ip, kind, reason: v.reason || '', note: v.note || '' },
      })
      message.success('已加入' + KIND_LABEL[kind] + '，采集器 5s 内热重载')
      setAddOpen(false)
      addForm.resetFields()
      load()
    } catch (e: any) {
      message.error(e?.message || '添加失败')
    } finally {
      setBusy('')
    }
  }

  const toggle = async (r: IpListRow) => {
    setBusy(`toggle-${r.id}`)
    try {
      await api(`/api/ip-lists/${r.id}`, { method: 'PATCH', body: { enabled: !r.enabled } })
      message.success(r.enabled ? '已停用' : '已启用')
      load()
    } catch (e: any) {
      message.error(e?.message || '操作失败')
    } finally {
      setBusy('')
    }
  }

  const remove = async (r: IpListRow) => {
    setBusy(`del-${r.id}`)
    try {
      await api(`/api/ip-lists/${r.id}`, { method: 'DELETE' })
      message.success('已删除')
      load()
    } catch (e: any) {
      message.error(e?.message || '删除失败')
    } finally {
      setBusy('')
    }
  }

  const bulkDelete = async () => {
    setBusy('bulk')
    try {
      const out = await api<any>('/api/ip-lists/bulk-delete', {
        method: 'POST',
        body: { ids: selected },
      })
      message.success(`已删除 ${out?.deleted?.length ?? 0} 条`)
      load()
    } catch (e: any) {
      message.error(e?.message || '批量删除失败')
    } finally {
      setBusy('')
    }
  }

  const doImport = async () => {
    let v: any
    try {
      v = await importForm.validateFields()
    } catch {
      return
    }
    if (!importText.trim()) {
      message.warning('请粘贴内容或选择文件')
      return
    }
    setBusy('import')
    try {
      const out = await api<any>('/api/ip-lists/import', {
        method: 'POST',
        body: { kind, text: importText },
      })
      message.success(
        `导入完成：新增 ${out.added}，更新 ${out.updated}，跳过 ${out.skipped?.length ?? 0}`,
      )
      setImportOpen(false)
      setImportText('')
      importForm.resetFields()
      load()
    } catch (e: any) {
      message.error(e?.message || '导入失败')
    } finally {
      setBusy('')
    }
  }

  const readFile = async (f: File | undefined) => {
    if (!f) return
    try {
      setImportText(await f.text())
      message.success(`已读入 ${f.name}`)
    } catch {
      message.error('读取文件失败')
    }
  }

  const exportList = async (fmt: 'csv' | 'json') => {
    try {
      await download(`/api/ip-lists/export?kind=${kind}&format=${fmt}`,
        `ip_${kind}.${fmt}`)
    } catch (e: any) {
      message.error(e?.message || '导出失败')
    }
  }

  const saveSettings = async (patch: Partial<IpAutoSettings>) => {
    try {
      const out = await api<any>('/api/ip-lists/settings', { method: 'PUT', body: patch })
      setSettings(out.settings)
      message.success('自动拉黑设置已保存')
    } catch (e: any) {
      message.error(e?.message || '保存失败')
    }
  }

  const scanNow = async () => {
    setBusy('scan')
    try {
      const out = await api<any>('/api/ip-lists/auto/scan', { method: 'POST' })
      message.success(`扫描完成：候选 ${out?.candidates ?? 0}，新增黑名单 ${out?.added?.length ?? 0}`)
      load()
    } catch (e: any) {
      message.error(e?.message || '扫描失败')
    } finally {
      setBusy('')
    }
  }

  const columns = useMemo(() => [
    { title: 'IP / CIDR', dataIndex: 'ip', width: 200, render: (v: string) => <Text code>{v}</Text> },
    {
      title: '类型',
      dataIndex: 'kind',
      width: 90,
      render: (v: string) => <Tag color={KIND_COLOR[v]}>{KIND_LABEL[v] || v}</Tag>,
    },
    {
      title: '来源',
      dataIndex: 'source',
      width: 100,
      render: (v: string) => (v === 'auto' ? <Tag color="orange">自动</Tag> : <Tag>手工</Tag>),
    },
    { title: '原因', dataIndex: 'reason', ellipsis: true },
    {
      title: '过期',
      dataIndex: 'expires_at',
      width: 170,
      render: (v: number | null, r: IpListRow) =>
        r.expired ? <Tag color="default">已过期</Tag>
          : v ? fmtTs(v) : <span className="muted">永久</span>,
    },
    {
      title: '状态',
      dataIndex: 'enabled',
      width: 90,
      render: (v: boolean, r: IpListRow) =>
        <Tag color={v && !r.expired ? 'green' : 'default'}>{v && !r.expired ? '生效' : '停用'}</Tag>,
    },
    { title: '操作人', dataIndex: 'created_by', width: 100 },
    { title: '时间', dataIndex: 'created_at', width: 165, render: (v: number) => fmtTs(v) },
    {
      title: '操作',
      width: 190,
      render: (_: any, r: IpListRow) => (
        <Space size={4} wrap>
          <Button size="small" disabled={!canWrite} loading={busy === `toggle-${r.id}`}
                  onClick={() => toggle(r)}>
            {r.enabled ? '停用' : '启用'}
          </Button>
          {isAdmin ? (
            <Popconfirm title={`删除 ${r.ip}？`} onConfirm={() => remove(r)}>
              <Button size="small" danger icon={<DeleteOutlined />}
                      loading={busy === `del-${r.id}`} />
            </Popconfirm>
          ) : null}
        </Space>
      ),
    },
  ], [busy, canWrite, isAdmin, kind])

  return (
    <div>
      <div className="toolbar">
        <Title level={4} className="page-title">IP 黑白名单</Title>
        <Button icon={<ReloadOutlined />} onClick={load} loading={loading}>刷新</Button>
        <Button type="primary" icon={<PlusOutlined />} disabled={!canWrite}
                onClick={() => {
                  addForm.resetFields()
                  setAddOpen(true)
                }}>
          添加
        </Button>
        <Button icon={<UploadOutlined />} disabled={!canWrite}
                onClick={() => {
                  importForm.resetFields()
                  setImportText('')
                  setImportOpen(true)
                }}>
          批量导入
        </Button>
        <Button icon={<DownloadOutlined />} onClick={() => exportList('csv')}>导出 CSV</Button>
        <Button icon={<DownloadOutlined />} onClick={() => exportList('json')}>导出 JSON</Button>
        {selected.length ? (
          <Button danger disabled={!isAdmin} loading={busy === 'bulk'} onClick={bulkDelete}>
            删除选中（{selected.length}）
          </Button>
        ) : null}
      </div>

      <Alert
        type="info"
        showIcon
        style={{ marginBottom: 12 }}
        message="生效顺序：白名单优先 → 黑名单 → 规则/模型"
        description={
          <span>
            白名单命中直接放行（跳过模型/规则，仍留事件）；黑名单在 enforce 下 403、
            dry-run 只记录；off 纯采集不应用名单。支持 IPv4/IPv6 与 CIDR。
            当前生效：黑 {counts.black ?? 0} / 白 {counts.white ?? 0}；
            产物 {artifact?.present ? `已生成（更新 ${fmtTs(artifact.mtime)}）` : '尚未生成'}。
          </span>
        }
      />
      {err ? <Alert type="error" showIcon message={err} style={{ marginBottom: 12 }} /> : null}

      <Card size="small">
        <Tabs
          activeKey={kind}
          onChange={(k) => setKind(k as 'black' | 'white')}
          items={[
            { key: 'black', label: `黑名单（${counts.black ?? 0}）` },
            { key: 'white', label: `白名单（${counts.white ?? 0}）` },
          ]}
        />
        <Table<IpListRow>
          size="small"
          rowKey="id"
          loading={loading}
          dataSource={items}
          columns={columns as any}
          rowSelection={isAdmin ? {
            selectedRowKeys: selected,
            preserveSelectedRowKeys: true,
            onChange: (keys) => setSelected(keys as number[]),
          } : undefined}
          pagination={{ pageSize: 20, showSizeChanger: true }}
        />
      </Card>

      {isAdmin && settings ? (
        <Card size="small" title="自动拉黑（同一 IP 多次告警）" style={{ marginTop: 12 }}>
          <Descriptions size="small" column={3} bordered style={{ marginBottom: 12 }}>
            <Descriptions.Item label="总开关">
              <Switch checked={settings.enabled} onChange={(v) => saveSettings({ enabled: v })} />
            </Descriptions.Item>
            <Descriptions.Item label="阈值（次数）">
              <InputNumber min={1} max={10000} value={settings.threshold}
                onChange={(v) => v && saveSettings({ threshold: Number(v) })} />
            </Descriptions.Item>
            <Descriptions.Item label="窗口（分钟）">
              <InputNumber min={1} max={1440} value={settings.window_min}
                onChange={(v) => v && saveSettings({ window_min: Number(v) })} />
            </Descriptions.Item>
            <Descriptions.Item label="拉黑时长（小时，0=永久）">
              <InputNumber min={0} max={8760} value={settings.duration_hours}
                onChange={(v) => v !== null && saveSettings({ duration_hours: Number(v) })} />
            </Descriptions.Item>
            <Descriptions.Item label="统计规则命中的 alert">
              <Switch checked={settings.count_rule_alerts}
                onChange={(v) => saveSettings({ count_rule_alerts: v })} />
            </Descriptions.Item>
            <Descriptions.Item label="手动扫一轮">
              <Button size="small" loading={busy === 'scan'} onClick={scanNow}>立即扫描</Button>
            </Descriptions.Item>
          </Descriptions>
          <div className="muted">
            只统计窗口内<b>有规则命中的 alert</b> 和 <b>block</b>；白名单 IP 永远不会被自动拉黑；
            自动条目默认 24 小时后过期，手工条目不自动过期。
          </div>
        </Card>
      ) : null}

      <Modal
        open={addOpen}
        title={`添加到${KIND_LABEL[kind]}`}
        okText="添加"
        confirmLoading={busy === 'add'}
        onCancel={() => setAddOpen(false)}
        onOk={add}
        destroyOnClose
      >
        <Form form={addForm} layout="vertical" size="small">
          <Form.Item name="ip" label="IP 或 CIDR"
            rules={[{ required: true, message: '请输入 IP / CIDR' }]}>
            <Input placeholder="例如：203.0.113.9 或 203.0.113.0/24" />
          </Form.Item>
          <Form.Item name="reason" label="原因">
            <Input placeholder="例如：扫描器 / 多次攻击 / 合作方固定出口" />
          </Form.Item>
          <Form.Item name="note" label="备注">
            <Input.TextArea rows={2} />
          </Form.Item>
        </Form>
      </Modal>

      <Modal
        open={importOpen}
        title={`批量导入到${KIND_LABEL[kind]}`}
        okText="导入"
        confirmLoading={busy === 'import'}
        onCancel={() => setImportOpen(false)}
        onOk={doImport}
        width={720}
        destroyOnClose
      >
        <Alert
          type="info"
          showIcon
          style={{ marginBottom: 12 }}
          message="支持 JSON / CSV / 纯文本"
          description={
            <span>
              JSON：<Text code>{'[{"ip":"1.2.3.4","reason":"scanner"}]'}</Text>；
              CSV：表头 <Text code>ip,kind,reason,note</Text>（kind 可省略，默认当前页签）；
              纯文本：每行 <Text code>ip[,原因[,备注]]</Text>。非法的行会跳过并回报。
            </span>
          }
        />
        <Form form={importForm} layout="vertical" size="small">
          <Form.Item label="选择文件（可选）">
            <input type="file" accept=".csv,.tsv,.txt,.json"
                   onChange={(e) => readFile(e.target.files?.[0])} />
          </Form.Item>
          <Form.Item label="内容">
            <Input.TextArea rows={8} value={importText}
                            onChange={(e) => setImportText(e.target.value)}
                            placeholder="1.2.3.4,扫描器&#10;10.0.0.0/8,内网" />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  )
}