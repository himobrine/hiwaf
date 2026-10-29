import { useCallback, useEffect, useState } from 'react'
import {
  Alert,
  Button,
  Card,
  Descriptions,
  Form,
  Input,
  InputNumber,
  Modal,
  Select,
  Space,
  Table,
  Tag,
  Tooltip,
  Typography,
  message,
} from 'antd'
import { PlusOutlined, ReloadOutlined, ThunderboltOutlined } from '@ant-design/icons'
import { api, fmtTs } from '../api'
import type { Suppression, User } from '../types'

const { Title, Text } = Typography

const STATUS_COLOR: Record<string, string> = {
  draft: 'gold',
  active: 'green',
  revoked: 'red',
  expired: 'default',
}

const STATUS_LABEL: Record<string, string> = {
  draft: '草案',
  active: '生效中',
  revoked: '已撤销',
  expired: '已过期',
}

const ENTITY_FIELDS = [
  { name: 'src_ip', label: '源 IP' },
  { name: 'path', label: '路径' },
  { name: 'ua', label: 'UA' },
  { name: 'host', label: 'Host' },
  { name: 'attack_type', label: '攻击类型' },
] as const

/** 实体标签：只显示非空字段，多个字段是 AND。 */
function entityTags(row: Suppression) {
  const bits = ENTITY_FIELDS.filter((f) => (row as any)[f.name])
  if (!bits.length) return <span className="muted">-</span>
  return (
    <Space size={2} wrap>
      {bits.map((f) => (
        <Tag key={f.name} color={f.name === 'src_ip' ? 'blue' : 'geekblue'}>
          {f.label}: {String((row as any)[f.name])}
        </Tag>
      ))}
    </Space>
  )
}

export default function Suppressions({ user }: { user: User }) {
  const canWrite = user.role !== 'viewer'
  const canApprove = user.role === 'admin'

  const [items, setItems] = useState<Suppression[]>([])
  const [status, setStatus] = useState<string>('')
  const [loading, setLoading] = useState(false)
  const [err, setErr] = useState('')
  const [pageSize, setPageSize] = useState(50)
  const [limits, setLimits] = useState({ default: 168, max: 2160 })

  // 新建草案
  const [createOpen, setCreateOpen] = useState(false)
  const [creating, setCreating] = useState(false)
  const [form] = Form.useForm()

  // 从误报生成
  const [suggestOpen, setSuggestOpen] = useState(false)
  const [suggesting, setSuggesting] = useState(false)
  const [suggestResult, setSuggestResult] = useState<any>(null)
  const [suggestForm] = Form.useForm()

  // 审批/撤销备注
  const [decision, setDecision] = useState<{ row: Suppression; kind: 'approve' | 'revoke' } | null>(
    null,
  )
  const [decisionNote, setDecisionNote] = useState('')
  const [deciding, setDeciding] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    setErr('')
    try {
      const q = status ? `?status=${status}&limit=500` : '?limit=500'
      const r = await api<any>(`/api/suppressions${q}`)
      setItems(r.items || [])
      setLimits({
        default: Number(r.default_ttl_hours || 168),
        max: Number(r.max_ttl_hours || 2160),
      })
    } catch (e: any) {
      setErr(e?.message || '加载失败')
    } finally {
      setLoading(false)
    }
  }, [status])

  useEffect(() => {
    load()
  }, [load])

  const openCreate = () => {
    form.resetFields()
    form.setFieldsValue({ ttl_hours: limits.default })
    setCreateOpen(true)
  }

  const submitCreate = async () => {
    let v: any
    try {
      v = await form.validateFields()
    } catch {
      return
    }
    const body: any = { reason: v.reason, ttl_hours: v.ttl_hours }
    for (const f of ENTITY_FIELDS) {
      const val = typeof v[f.name] === 'string' ? v[f.name].trim() : v[f.name]
      if (val) body[f.name] = val
    }
    if (!ENTITY_FIELDS.some((f) => body[f.name])) {
      message.error('至少填一个实体字段（源 IP / 路径 / UA / Host / 攻击类型）')
      return
    }
    if (body.path && !body.path.startsWith('/')) {
      message.error('路径必须以 / 开头')
      return
    }
    if (v.note) body.note = v.note
    setCreating(true)
    try {
      await api('/api/suppressions', { method: 'POST', body })
      message.success('已创建草案，需 admin 审批后才生效')
      setCreateOpen(false)
      load()
    } catch (e: any) {
      message.error(e?.message || '创建失败')
    } finally {
      setCreating(false)
    }
  }

  const openSuggest = () => {
    suggestForm.setFieldsValue({
      days: 30,
      min_count: 3,
      ttl_hours: limits.default,
    })
    setSuggestResult(null)
    setSuggestOpen(true)
  }

  const submitSuggest = async () => {
    let v: any
    try {
      v = await suggestForm.validateFields()
    } catch {
      return
    }
    setSuggesting(true)
    try {
      const r = await api<any>('/api/suppressions/suggest', { method: 'POST', body: v })
      setSuggestResult(r)
      if ((r.created || []).length) {
        message.success(`已生成 ${r.created.length} 条草案`)
        load()
      } else {
        message.info('没有新的可生成草案（可能未达阈值或已被覆盖）')
      }
    } catch (e: any) {
      message.error(e?.message || '生成失败')
    } finally {
      setSuggesting(false)
    }
  }

  const submitDecision = async () => {
    if (!decision) return
    setDeciding(true)
    try {
      await api(`/api/suppressions/${decision.row.id}/${decision.kind}`, {
        method: 'POST',
        body: { note: decisionNote.trim() || undefined },
      })
      message.success(decision.kind === 'approve' ? '已通过并生效' : '已撤销')
      setDecision(null)
      setDecisionNote('')
      load()
    } catch (e: any) {
      message.error(e?.message || '操作失败')
    } finally {
      setDeciding(false)
    }
  }

  const doDelete = (row: Suppression) => {
    Modal.confirm({
      title: `删除抑制 #${row.id}？`,
      content: '只允许删除草案/已撤销行；生效中的必须先撤销，审批轨迹会保留在审计里。',
      okText: '删除',
      okButtonProps: { danger: true },
      onOk: async () => {
        try {
          await api(`/api/suppressions/${row.id}`, { method: 'DELETE' })
          message.success('已删除')
          load()
        } catch (e: any) {
          message.error(e?.message || '删除失败')
        }
      },
    })
  }

  const ops = (row: Suppression) => {
    if (!canWrite) return <span className="muted">只读</span>
    return (
      <Space size={4}>
        {row.status === 'draft' && canApprove ? (
          <Button
            size="small"
            type="primary"
            onClick={() => {
              setDecision({ row, kind: 'approve' })
              setDecisionNote('')
            }}
          >
            通过
          </Button>
        ) : null}
        {row.status === 'draft' || row.status === 'active' ? (
          <Button
            size="small"
            danger
            onClick={() => {
              setDecision({ row, kind: 'revoke' })
              setDecisionNote('')
            }}
          >
            撤销
          </Button>
        ) : null}
        {row.status === 'draft' || row.status === 'revoked' ? (
          <Button size="small" onClick={() => doDelete(row)}>
            删除
          </Button>
        ) : null}
      </Space>
    )
  }

  return (
    <div>
      <div className="toolbar">
        <Title level={4} className="page-title">
          抑制策略
        </Title>
        <Select
          value={status}
          onChange={setStatus}
          style={{ width: 140 }}
          options={[
            { value: '', label: '全部状态' },
            { value: 'draft', label: '草案' },
            { value: 'active', label: '生效中' },
            { value: 'revoked', label: '已撤销' },
            { value: 'expired', label: '已过期' },
          ]}
        />
        <Button icon={<ReloadOutlined />} onClick={() => load()}>
          刷新
        </Button>
        {canWrite ? (
          <>
            <Button icon={<PlusOutlined />} onClick={openCreate}>
              新建草案
            </Button>
            <Button icon={<ThunderboltOutlined />} onClick={openSuggest}>
              从误报生成草案
            </Button>
          </>
        ) : null}
      </div>

      <Alert
        type="warning"
        showIcon
        style={{ marginBottom: 12 }}
        message="抑制只折叠控制台的告警可见性，不改数据面判定：被抑制的命中仍会拦截/告警，只是不再刷屏。"
        description={
          <span className="muted">
            一条抑制由若干实体字段组成，多个字段是 AND（同时满足才命中），至少填一个。
            草案（draft）默认不生效，需 admin 审批后带 TTL 生效；到期自动过期，撤销/过期后进入冷却期，避免自动草案反复冒出来。
          </span>
        }
      />
      {err ? <Alert type="error" message={err} showIcon style={{ marginBottom: 12 }} /> : null}

      <Card size="small">
        <Table
          size="small"
          rowKey="id"
          loading={loading}
          dataSource={items}
          pagination={{
            pageSize,
            showSizeChanger: true,
            pageSizeOptions: ['20', '50', '100', '200'],
            onShowSizeChange: (_p, ps) => setPageSize(ps),
            showTotal: (n) => `共 ${n} 条`,
          }}
          columns={[
            { title: 'ID', dataIndex: 'id', width: 70 },
            {
              title: '实体（AND）',
              width: 380,
              render: (_: any, r: Suppression) => entityTags(r),
            },
            {
              title: '原因',
              dataIndex: 'reason',
              ellipsis: true,
              render: (v: string, r: Suppression) => (
                <Tooltip title={r.note ? `${v}\n${r.note}` : v}>
                  <span>{v}</span>
                </Tooltip>
              ),
            },
            {
              title: '状态',
              dataIndex: 'status',
              width: 96,
              render: (v: string) => <Tag color={STATUS_COLOR[v] || 'default'}>{STATUS_LABEL[v] || v}</Tag>,
            },
            {
              title: 'TTL / 到期',
              width: 190,
              render: (_: any, r: Suppression) => (
                <span>
                  {r.ttl_hours}h
                  {r.expires_at ? (
                    <span className="muted"> · {fmtTs(r.expires_at)}</span>
                  ) : null}
                </span>
              ),
            },
            {
              title: '创建 / 审批',
              width: 230,
              render: (_: any, r: Suppression) => (
                <span className="muted">
                  {r.created_by || '-'} · {fmtTs(r.created_at)}
                  {r.approved_by ? (
                    <>
                      <br />
                      审批 {r.approved_by} · {fmtTs(r.approved_at)}
                    </>
                  ) : null}
                  {r.revoked_by ? (
                    <>
                      <br />
                      撤销 {r.revoked_by} · {fmtTs(r.revoked_at)}
                    </>
                  ) : null}
                </span>
              ),
            },
            {
              title: '操作',
              width: 190,
              render: (_: any, r: Suppression) => ops(r),
            },
          ]}
        />
      </Card>

      {/* ---------------------------------------------------- 新建草案 */}
      <Modal
        open={createOpen}
        title="新建抑制草案"
        okText="保存为草案"
        confirmLoading={creating}
        onCancel={() => setCreateOpen(false)}
        onOk={submitCreate}
        width={680}
        destroyOnClose
      >
        <Alert
          type="info"
          showIcon
          style={{ marginBottom: 12 }}
          message="多个实体字段是 AND：例如源 IP + 攻击类型 = 只压这个源的该类告警，不会关掉整条规则。"
        />
        <Form form={form} layout="vertical" size="small">
          <Space size={12} wrap>
            <Form.Item name="src_ip" label="源 IP">
              <Input placeholder="1.2.3.4" style={{ width: 180 }} />
            </Form.Item>
            <Form.Item name="path" label="路径（以 / 开头）">
              <Input placeholder="/login" style={{ width: 220 }} />
            </Form.Item>
            <Form.Item name="host" label="Host">
              <Input placeholder="example.com" style={{ width: 200 }} />
            </Form.Item>
            <Form.Item name="ua" label="User-Agent">
              <Input placeholder="curl/8.0" style={{ width: 220 }} />
            </Form.Item>
            <Form.Item name="attack_type" label="攻击类型">
              <Input placeholder="xss" style={{ width: 160 }} />
            </Form.Item>
            <Form.Item name="ttl_hours" label="TTL（小时）">
              <InputNumber min={1} max={limits.max} style={{ width: 140 }} />
            </Form.Item>
          </Space>
          <Form.Item name="reason" label="原因" rules={[{ required: true, message: '写清楚为什么抑制' }]}>
            <Input.TextArea rows={2} maxLength={500} placeholder="例如：该 IP 的 XSS 命中经人工确认全部为误报" />
          </Form.Item>
          <Form.Item name="note" label="备注（可选）">
            <Input.TextArea rows={2} maxLength={500} placeholder="关联工单、复现路径等" />
          </Form.Item>
        </Form>
      </Modal>

      {/* ---------------------------------------------------- 从误报生成 */}
      <Modal
        open={suggestOpen}
        title="从人工确认误报生成草案"
        okText="扫描并生成草案"
        confirmLoading={suggesting}
        onCancel={() => setSuggestOpen(false)}
        onOk={submitSuggest}
        width={640}
      >
        <Alert
          type="info"
          showIcon
          style={{ marginBottom: 12 }}
          message="按「源 IP + 攻击类型」统计近 N 天 feedback=false_positive，达到阈值才生成草案；已有草案/生效抑制或撤销冷却期内会跳过。只生成草案，不会自动生效。"
        />
        <Form form={suggestForm} layout="vertical" size="small">
          <Space size={12} wrap>
            <Form.Item name="days" label="统计窗口（天）">
              <InputNumber min={1} max={365} style={{ width: 140 }} />
            </Form.Item>
            <Form.Item name="min_count" label="最少确认误报数">
              <InputNumber min={1} max={1000} style={{ width: 150 }} />
            </Form.Item>
            <Form.Item name="ttl_hours" label="草案 TTL（小时）">
              <InputNumber min={1} max={limits.max} style={{ width: 150 }} />
            </Form.Item>
          </Space>
        </Form>
        {suggestResult ? (
          <Descriptions size="small" bordered column={3} style={{ marginTop: 8 }}>
            <Descriptions.Item label="命中实体组">{suggestResult.scanned ?? 0}</Descriptions.Item>
            <Descriptions.Item label="新建草案">
              <Text strong>{(suggestResult.created || []).length}</Text>
            </Descriptions.Item>
            <Descriptions.Item label="跳过">{(suggestResult.skipped || []).length}</Descriptions.Item>
          </Descriptions>
        ) : null}
        {suggestResult?.skipped?.length ? (
          <div style={{ marginTop: 8 }}>
            {suggestResult.skipped.map((s: any, i: number) => (
              <div key={i} className="muted">
                {s.src_ip}
                {s.attack_type ? ` / ${s.attack_type}` : ''} ×{s.n}：{s.why}
              </div>
            ))}
          </div>
        ) : null}
      </Modal>

      {/* ---------------------------------------------------- 审批 / 撤销 */}
      <Modal
        open={!!decision}
        title={
          decision
            ? `${decision.kind === 'approve' ? '通过' : '撤销'}抑制 #${decision.row.id}`
            : ''
        }
        okText={decision?.kind === 'approve' ? '通过并生效' : '确认撤销'}
        okButtonProps={{ danger: decision?.kind === 'revoke' }}
        confirmLoading={deciding}
        onCancel={() => setDecision(null)}
        onOk={submitDecision}
        width={560}
      >
        {decision ? (
          <>
            <Descriptions size="small" bordered column={2} style={{ marginBottom: 12 }}>
              <Descriptions.Item label="实体" span={2}>
                {entityTags(decision.row)}
              </Descriptions.Item>
              <Descriptions.Item label="TTL">{decision.row.ttl_hours}h</Descriptions.Item>
              <Descriptions.Item label="原因">{decision.row.reason}</Descriptions.Item>
            </Descriptions>
            <Input.TextArea
              rows={2}
              maxLength={500}
              value={decisionNote}
              onChange={(e) => setDecisionNote(e.target.value)}
              placeholder={
                decision.kind === 'approve' ? '审批备注（可选）' : '撤销原因（可选，会进审计）'
              }
            />
          </>
        ) : null}
      </Modal>
    </div>
  )
}
