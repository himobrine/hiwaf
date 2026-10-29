import { useCallback, useEffect, useRef, useState } from 'react'
import {
  Alert,
  Button,
  Descriptions,
  Form,
  Input,
  InputNumber,
  Modal,
  Radio,
  Select,
  Space,
  Switch,
  Table,
  Tag,
  Tooltip,
  Typography,
  message,
} from 'antd'
import { DatabaseOutlined, ReloadOutlined, SearchOutlined } from '@ant-design/icons'
import { api, fmtNum, fmtTs } from '../api'
import type { EventRow, User } from '../types'
import EventDetailDrawer, { ActionTag } from '../components/EventDetailDrawer'

const { Title, Text } = Typography

const ROLE_OPTIONS = [
  { value: 'supervised', label: '监督训练（逐行标签，XGBoost）' },
  { value: 'benign', label: '良性样本（零日训练 / 阈值校准）' },
  { value: 'eval', label: '仅评估（不参与训练）' },
]

const LABEL_OPTIONS = [
  { value: 0, label: '0 · normal（良性）' },
  { value: 1, label: '1 · sqli（未细分攻击也用 1）' },
  { value: 2, label: '2 · xss' },
  { value: 3, label: '3 · cmdi' },
  { value: 4, label: '4 · traversal' },
]

/** keyset 游标：上一页最后一条的 (ts, id)。 */
type Cursor = { ts: number; id: number }

export default function Events({ user }: { user: User }) {
  const [rows, setRows] = useState<EventRow[]>([])
  const [total, setTotal] = useState<number | null>(null)
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(50)
  const [hasMore, setHasMore] = useState(false)
  const [loading, setLoading] = useState(false)
  const [err, setErr] = useState('')
  // 每页的起点游标；cursors[0] = null（第一页用 offset=0）。
  const cursorsRef = useRef<(Cursor | null)[]>([null])
  const [refreshTick, setRefreshTick] = useState(0)

  const [action, setAction] = useState<string | undefined>(undefined)
  const [srcIp, setSrcIp] = useState('')
  const [path, setPath] = useState('')
  const [q, setQ] = useState('')
  const [minScore, setMinScore] = useState<number | undefined>(undefined)
  const [onlyTesting, setOnlyTesting] = useState(false)

  const [detailId, setDetailId] = useState<number | null>(null)

  // 从事件建训练数据集：勾选（跨页保留）或按当前筛选全量。
  const [selected, setSelected] = useState<number[]>([])
  const [trainOpen, setTrainOpen] = useState(false)
  const [scope, setScope] = useState<'ids' | 'filter'>('ids')
  const [preview, setPreview] = useState<any>(null)
  const [previewing, setPreviewing] = useState(false)
  const [creating, setCreating] = useState(false)
  const [roleSel, setRoleSel] = useState('supervised')
  const [trainForm] = Form.useForm()
  const canCurate = user.role !== 'viewer'

  /** 当前工具栏筛选（与列表用的是同一组状态）。 */
  const buildFilters = useCallback(() => {
    const f: any = {}
    if (action) f.action = action
    if (srcIp) f.src_ip = srcIp
    if (path) f.path = path
    if (q) f.q = q
    if (minScore !== undefined && minScore !== null) f.min_score = minScore
    if (onlyTesting) f.rule_testing = true
    return f
  }, [action, srcIp, path, q, minScore, onlyTesting])

  const openTrain = () => {
    const hasFilters = Object.keys(buildFilters()).length > 0
    const next = selected.length ? 'ids' : hasFilters ? 'filter' : 'ids'
    setScope(next)
    setPreview(null)
    setRoleSel('supervised')
    trainForm.setFieldsValue({
      role: 'supervised',
      label: 1,
      name: `事件数据集 ${new Date().toLocaleString()}`,
      source_note: '',
      max_rows: undefined,
    })
    setTrainOpen(true)
  }

  const doPreview = useCallback(
    async (nextScope = scope) => {
      const body: any = { mode: nextScope }
      if (nextScope === 'ids') {
        if (!selected.length) {
          message.warning('先勾选事件，或改用「按当前筛选」')
          return
        }
        body.event_ids = selected
      } else {
        const f = buildFilters()
        if (!Object.keys(f).length) {
          message.warning('当前没有任何筛选条件，请先设置筛选')
          return
        }
        body.filters = f
      }
      const maxRows = trainForm.getFieldValue('max_rows')
      if (maxRows) body.max_rows = Number(maxRows)
      setPreviewing(true)
      setPreview(null)
      try {
        setPreview(await api<any>('/api/events/selection-preview', { method: 'POST', body }))
      } catch (e: any) {
        message.error(e?.message || '预检失败')
      } finally {
        setPreviewing(false)
      }
    },
    [scope, selected, buildFilters, trainForm],
  )

  const submitTrain = async () => {
    let v: any
    try {
      v = await trainForm.validateFields()
    } catch {
      return
    }
    const body: any = {
      name: v.name || '',
      role: v.role,
      label: Number(v.label),
      source_note: v.source_note || '',
      mode: scope,
    }
    if (scope === 'ids') body.event_ids = selected
    else body.filters = buildFilters()
    if (v.max_rows) body.max_rows = Number(v.max_rows)
    setCreating(true)
    try {
      const r = await api<any>('/api/uploads/from-events', { method: 'POST', body })
      message.success(`数据集 #${r.id} 已创建（后台固化事件），可在「训练数据」页查看`)
      setTrainOpen(false)
      setSelected([])
      setPreview(null)
    } catch (e: any) {
      message.error(e?.message || '创建失败')
    } finally {
      setCreating(false)
    }
  }

  const resetPaging = () => {
    cursorsRef.current = [null]
    setPage(1)
  }

  const load = useCallback(async (silent = false) => {
    if (!silent) setLoading(true)
    setErr('')
    try {
      const cursor = cursorsRef.current[page - 1] ?? null
      const p = new URLSearchParams()
      p.set('limit', String(pageSize))
      // keyset 翻页：只按 (ts,id) 定位，不扫描/丢弃前 N 行。
      if (cursor) {
        p.set('cursor_ts', String(cursor.ts))
        p.set('cursor_id', String(cursor.id))
      }
      // 只有第一页统计总数；翻页沿用第一页的 total，省掉重复 COUNT(*)。
      p.set('with_total', page === 1 ? '1' : '0')
      if (page === 1) p.set('offset', '0')
      if (action) p.set('action', action)
      if (srcIp) p.set('src_ip', srcIp)
      if (path) p.set('path', path)
      if (q) p.set('q', q)
      if (minScore !== undefined && minScore !== null) p.set('min_score', String(minScore))
      if (onlyTesting) p.set('rule_testing', '1')
      const r = await api<any>(`/api/events?${p.toString()}`)
      setRows(r.items || [])
      if (typeof r.total === 'number') setTotal(r.total)
      setHasMore(!!r.has_more)
      if (r.next_cursor) cursorsRef.current[page] = r.next_cursor
    } catch (e: any) {
      setErr(e?.message || '加载失败')
    } finally {
      if (!silent) setLoading(false)
    }
  }, [page, pageSize, action, srcIp, path, q, minScore, onlyTesting, refreshTick])

  useEffect(() => {
    load()
    const timer = setInterval(() => load(true), 15000)
    return () => clearInterval(timer)
  }, [load])

  return (
    <div>
      <div className="toolbar">
        <Title level={4} className="page-title">
          事件
        </Title>
        <Select
          placeholder="动作"
          allowClear
          style={{ width: 120 }}
          value={action}
          onChange={(v) => {
            resetPaging()
            setAction(v)
          }}
          options={[
            { value: 'block', label: 'block' },
            { value: 'alert', label: 'alert' },
            { value: 'allow', label: 'allow' },
          ]}
        />
        <Input
          placeholder="源 IP"
          style={{ width: 150 }}
          value={srcIp}
          onChange={(e) => setSrcIp(e.target.value)}
          onPressEnter={() => {
            resetPaging()
            setRefreshTick((v) => v + 1)
          }}
        />
        <Input
          placeholder="路径包含"
          style={{ width: 180 }}
          value={path}
          onChange={(e) => setPath(e.target.value)}
          onPressEnter={() => {
            resetPaging()
            setRefreshTick((v) => v + 1)
          }}
        />
        <Input
          placeholder="关键字（路径/查询/UA）"
          style={{ width: 200 }}
          value={q}
          onChange={(e) => setQ(e.target.value)}
          onPressEnter={() => {
            resetPaging()
            setRefreshTick((v) => v + 1)
          }}
        />
        <InputNumber
          placeholder="最小监督分"
          min={0}
          max={1}
          step={0.1}
          style={{ width: 140 }}
          value={minScore}
          onChange={(v) => setMinScore(v === null ? undefined : Number(v))}
        />
        <Tooltip title="只看命中了「未合格、测试中」规则的事件（rule_testing=1）">
          <Space size={4}>
            <Switch
              size="small"
              checked={onlyTesting}
              onChange={(v) => {
                resetPaging()
                setOnlyTesting(v)
              }}
            />
            <span className="muted">只看测试命中</span>
          </Space>
        </Tooltip>
        <Button
          icon={<SearchOutlined />}
          type="primary"
          onClick={() => {
            resetPaging()
            setRefreshTick((v) => v + 1)
          }}
        >
          查询
        </Button>
        <Button
          icon={<ReloadOutlined />}
          onClick={() => setRefreshTick((v) => v + 1)}
        >
          刷新
        </Button>
        <Tooltip title="把勾选的事件（或按当前筛选）固化成训练数据集；标签必须人工指定，不会用模型预测当标签">
          <Button
            type="primary"
            ghost
            icon={<DatabaseOutlined />}
            onClick={openTrain}
            disabled={!canCurate}
          >
            加入训练数据{selected.length ? `（${selected.length}）` : ''}
          </Button>
        </Tooltip>
        <span className="muted">自动刷新 15s</span>
      </div>

      {err ? <Alert type="error" message={err} showIcon style={{ marginBottom: 12 }} /> : null}

      <Table<EventRow>
        size="small"
        rowKey="id"
        loading={loading}
        dataSource={rows}
        rowSelection={{
          selectedRowKeys: selected,
          preserveSelectedRowKeys: true,
          onChange: (keys) => setSelected(keys as number[]),
        }}
        onRow={(r) => ({
          onClick: (e) => {
            // 点勾选框/全选不应打开事件详情抽屉。
            if ((e.target as HTMLElement).closest('.ant-table-selection-column')) return
            setDetailId(r.id)
          },
          style: { cursor: 'pointer' },
        })}
        pagination={false}
        columns={[
          { title: '时间', dataIndex: 'ts', width: 165, render: (v) => fmtTs(v) },
          { title: '源 IP', dataIndex: 'src_ip', width: 130 },
          { title: '方法', dataIndex: 'method', width: 70 },
          { title: '路径', dataIndex: 'path', ellipsis: true },
          { title: '状态码', dataIndex: 'status', width: 76 },
          {
            title: '动作',
            dataIndex: 'action',
            width: 88,
            render: (v) => <ActionTag a={v} />,
          },
          {
            title: '名单',
            width: 90,
            render: (_: any, r: EventRow) =>
              r.ip_list === 'blacklist' ? (
                <Tag color="red">黑名单</Tag>
              ) : r.ip_list === 'whitelist' ? (
                <Tag color="green">白名单</Tag>
              ) : (
                <span className="muted">-</span>
              ),
          },
          {
            title: '规则',
            width: 96,
            render: (_: any, r: EventRow) =>
              r.rule_hits?.length ? (
                <Space size={2}>
                  <Tooltip title={r.rule_hits.map((h) => h.rule).join('、')}>
                    <Tag color={r.rule_hits.some((h) => h.action === 'block') ? 'red' : 'gold'}>
                      {r.rule_hits.length} 条
                    </Tag>
                  </Tooltip>
                  {r.rule_testing ? (
                    <Tooltip title="命中里包含「未合格、测试中」的规则：命中会真的产生 alert，用来判断它值不值得合格">
                      <Tag color="blue">测试</Tag>
                    </Tooltip>
                  ) : null}
                </Space>
              ) : (
                <span className="muted">-</span>
              ),
          },
          {
            title: '监督分 / 阈值',
            width: 160,
            render: (_: any, r: EventRow) => {
              const hit = (r.supervised_score ?? 0) >= (r.supervised_threshold ?? 1)
              return (
                <span>
                  <Text strong={hit} type={hit ? 'danger' : undefined}>
                    {fmtNum(r.supervised_score, 4)}
                  </Text>
                  <span className="muted"> / {fmtNum(r.supervised_threshold, 4)}</span>
                </span>
              )
            },
          },
          {
            title: '零日分',
            width: 120,
            render: (_: any, r: EventRow) => (
              <Tooltip
                title={`阈值 ${fmtNum(r.zero_day_threshold, 4)}｜原始穿阈=${
                  r.zero_day_score_crossed ? '是' : '否'
                }｜通道${r.zero_day_enabled ? '开' : '关'}`}
              >
                <span>{fmtNum(r.zero_day_score, 3)}</span>
              </Tooltip>
            ),
          },
          {
            title: '类型',
            dataIndex: 'attack_type',
            width: 100,
            render: (v) => (v ? <Tag color="volcano">{v}</Tag> : <span className="muted">-</span>),
          },
        ]}
      />

      <Space style={{ marginTop: 12 }} wrap>
        <Button size="small" disabled={page <= 1} onClick={() => setPage(page - 1)}>
          上一页
        </Button>
        <span className="muted">第 {page} 页</span>
        <Button size="small" disabled={!hasMore} onClick={() => setPage(page + 1)}>
          下一页
        </Button>
        <Select
          size="small"
          value={pageSize}
          style={{ width: 110 }}
          onChange={(v) => {
            resetPaging()
            setPageSize(v)
          }}
          options={[
            { value: 20, label: '20 条/页' },
            { value: 50, label: '50 条/页' },
            { value: 100, label: '100 条/页' },
            { value: 200, label: '200 条/页' },
          ]}
        />
        <span className="muted">
          {total === null ? '按时间倒序 · 游标翻页' : `共 ${total} 条（第一页统计）`}
        </span>
      </Space>

      <Modal
        open={trainOpen}
        width={760}
        title="从事件生成训练数据集"
        onCancel={() => setTrainOpen(false)}
        footer={[
          <Button key="preview" onClick={() => doPreview()} loading={previewing}>
            预检
          </Button>,
          <Button key="ok" type="primary" loading={creating} onClick={submitTrain}>
            创建数据集
          </Button>,
        ]}
      >
        <Alert
          type="info"
          showIcon
          style={{ marginBottom: 12 }}
          message="标签必须由你指定"
          description="事件的 attack_type 是模型预测，只作筛选/提示，绝不会自动变成训练标签。创建时会把选中的事件固化成快照（事件到期清理不影响数据集）。"
        />
        <Form form={trainForm} layout="vertical">
          <Form.Item label="选择范围">
            <Radio.Group
              value={scope}
              onChange={(e) => {
                setScope(e.target.value)
                setPreview(null)
              }}
            >
              <Radio.Button value="ids" disabled={!selected.length}>
                已勾选 {selected.length} 条
              </Radio.Button>
              <Radio.Button value="filter">按当前筛选全部</Radio.Button>
            </Radio.Group>
            {scope === 'filter' ? (
              <div className="muted" style={{ marginTop: 6 }}>
                当前筛选：
                <Text code>{JSON.stringify(buildFilters())}</Text>
              </div>
            ) : null}
          </Form.Item>
          <Form.Item
            name="name"
            label="名称"
            rules={[{ required: true, message: '给数据集起个名字' }]}
          >
            <Input placeholder="例如：sqlmap 扫描（确认为攻击）" />
          </Form.Item>
          <Form.Item name="role" label="角色" rules={[{ required: true }]}>
            <Select
              options={ROLE_OPTIONS}
              onChange={(v) => {
                setRoleSel(v)
                if (v === 'benign') trainForm.setFieldsValue({ label: 0 })
              }}
            />
          </Form.Item>
          <Form.Item
            name="label"
            label="标签（人工指定）"
            rules={[{ required: true }]}
            extra="良性数据集只能选 0；攻击类型不确定时选 1（与本地在野攻击池的标注口径一致）。"
          >
            <Select options={LABEL_OPTIONS} disabled={roleSel === 'benign'} />
          </Form.Item>
          <Form.Item name="max_rows" label="条数上限">
            <InputNumber min={1} max={20000} style={{ width: 200 }} placeholder="默认 20000" />
          </Form.Item>
          <Form.Item
            name="source_note"
            label="数据来源说明"
            rules={[{ required: true, message: '监督/良性数据必须填写出处' }]}
          >
            <Input.TextArea
              rows={2}
              placeholder="例如：红队演练确认的 sqlmap 流量；或某业务路径的确认良性访问"
            />
          </Form.Item>
        </Form>

        {preview ? (
          <div style={{ marginTop: 4 }}>
            <Descriptions size="small" column={2} bordered>
              <Descriptions.Item label="匹配事件">{preview.matched}</Descriptions.Item>
              <Descriptions.Item label="上限 / 截断">
                {preview.limit} / {preview.truncated ? '会截断' : '不截断'}
              </Descriptions.Item>
              <Descriptions.Item label="抽查">
                {preview.checked} 条{preview.preview_capped ? '（预检抽样）' : ''}
              </Descriptions.Item>
              <Descriptions.Item label="去重后 / 重复">
                {preview.unique_checked} / {preview.duplicates_checked}
              </Descriptions.Item>
              <Descriptions.Item label="body 来源（库 / raw）">
                {preview.body?.from_db ?? 0} / {preview.body?.from_raw ?? 0}
              </Descriptions.Item>
              <Descriptions.Item label="body 缺失 / 截断">
                {preview.body?.missing ?? 0} / {preview.body?.truncated ?? 0}
              </Descriptions.Item>
              <Descriptions.Item label="本来无 body（GET 等）">
                {preview.body?.empty ?? 0}
              </Descriptions.Item>
            </Descriptions>
            {Object.keys(preview.attack_type_hint || {}).length ? (
              <div className="muted" style={{ marginTop: 6 }}>
                模型分类提示（不是标签）：
                {Object.entries(preview.attack_type_hint)
                  .map(([k, v]) => ` ${k}:${v}`)
                  .join(' ')}
              </div>
            ) : null}
            {preview.body?.missing ? (
              <Alert
                type="warning"
                showIcon
                style={{ marginTop: 8 }}
                message={`抽查里有 ${preview.body.missing} 条拿不到 body（raw 可能已清理）；这些行会以空 body 参与训练。`}
              />
            ) : null}
          </div>
        ) : null}
      </Modal>

      <EventDetailDrawer
        eventId={detailId}
        onClose={() => setDetailId(null)}
        onSelect={setDetailId}
        user={user}
      />
    </div>
  )
}
