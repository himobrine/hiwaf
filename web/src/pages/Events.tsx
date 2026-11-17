import { useCallback, useEffect, useRef, useState } from 'react'
import {
  Alert,
  Button,
  Card,
  Descriptions,
  Form,
  Input,
  InputNumber,
  Modal,
  Popover,
  Select,
  Space,
  Switch,
  Table,
  Tag,
  Tooltip,
  Typography,
  message,
} from 'antd'
import { DatabaseOutlined, FilterOutlined, ReloadOutlined, SearchOutlined } from '@ant-design/icons'
import { api, fmtNum, fmtTs } from '../api'
import type { EventRow, User } from '../types'
import EventDetailDrawer, { ActionTag } from '../components/EventDetailDrawer'
import SelectionBuilder, {
  compactFilters,
  type EventFilters,
  type RuleFacet,
  type SelectionValue,
} from '../components/SelectionBuilder'

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

/** 文本类筛选（草稿 → 400ms 防抖 → 生效）。 */
type Filters = { srcIp: string; path: string; q: string; minScore?: number }

const REFRESH_KEY = 'waf_events_refresh_sec'
const REFRESH_PRESETS = [0, 5, 10, 15, 30, 60]

/** 读自动刷新间隔：默认 15s（与改造前一致），0 表示关闭。 */
function loadRefresh(): number {
  try {
    const raw = localStorage.getItem(REFRESH_KEY)
    if (raw === null) return 15
    const n = Number(raw)
    if (n === 0) return 0
    return Number.isFinite(n) && n >= 3 && n <= 3600 ? n : 15
  } catch {
    return 15
  }
}

/** 「最后一条事件距今多久」的人话描述。 */
function lagText(sec?: number | null) {
  if (sec === null || sec === undefined) return '未知'
  if (sec <= 1) return '刚刚'
  if (sec < 60) return `${sec}s 前`
  if (sec < 3600) return `${Math.round(sec / 60)}min 前`
  return `${Math.round(sec / 3600)}h 前`
}

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
  /** 只有最新一次请求能写列表：慢响应不能覆盖新筛选/新页的结果。 */
  const reqSeq = useRef(0)
  const inflight = useRef(0)
  const [lastLoaded, setLastLoaded] = useState<number | null>(null)

  const [action, setAction] = useState<string | undefined>(undefined)
  const [onlyTesting, setOnlyTesting] = useState(false)
  /** 高级筛选（方法/状态码/攻击类型/人工结论/命中规则/分数/时间…），与文本筛选同属 AND。 */
  const [advanced, setAdvanced] = useState<EventFilters>({})
  const [advOpen, setAdvOpen] = useState(false)
  const [advDraft, setAdvDraft] = useState<EventFilters>({})
  const [ruleOptions, setRuleOptions] = useState<RuleFacet[]>([])
  /** 输入框里的草稿：改了不发请求，400ms 后整体提交。 */
  const [draft, setDraft] = useState<Filters>({
    srcIp: '',
    path: '',
    q: '',
    minScore: undefined,
  })
  /** 真正参与查询的筛选：列表显示什么，就以它为准。 */
  const [applied, setApplied] = useState<Filters>(draft)

  // 自动刷新间隔（秒，0 = 关闭）；默认沿用改造前的 15s。
  const [refreshSec, setRefreshSec] = useState<number>(loadRefresh)
  const [customRefresh, setCustomRefresh] = useState<boolean>(
    () => !REFRESH_PRESETS.includes(loadRefresh()),
  )

  /** 入库状态（最后入库时间 / 库内总数）：区分「还没入库」和「列表没显示」。 */
  const [ingest, setIngest] = useState<any>(null)
  const ingestAt = useRef(0)

  const [detailId, setDetailId] = useState<number | null>(null)

  // 从事件建训练数据集：勾选（跨页保留）或按条件筛选。
  const [selected, setSelected] = useState<number[]>([])
  const [trainOpen, setTrainOpen] = useState(false)
  const [sel, setSel] = useState<SelectionValue>({ mode: 'ids', filters: {} })
  const [preview, setPreview] = useState<any>(null)
  const [previewing, setPreviewing] = useState(false)
  const [creating, setCreating] = useState(false)
  const [selecting, setSelecting] = useState(false)
  const [roleSel, setRoleSel] = useState('supervised')
  const [trainForm] = Form.useForm()
  const canCurate = user.role !== 'viewer'

  /** 当前生效的筛选（列表显示的就是它；建数据集也以它为准）。 */
  const buildFilters = useCallback((): EventFilters => {
    const f: EventFilters = { ...advanced }
    if (action) f.action = action
    if (applied.srcIp) f.src_ip = applied.srcIp
    if (applied.path) f.path = applied.path
    if (applied.q) f.q = applied.q
    if (applied.minScore !== undefined && applied.minScore !== null) {
      f.min_score = applied.minScore
    }
    if (onlyTesting) f.rule_testing = true
    return compactFilters(f)
  }, [action, applied, onlyTesting, advanced])

  const nAdvanced = Object.keys(advanced).length

  const openTrain = () => {
    const f = buildFilters()
    setSel({
      mode: selected.length ? 'ids' : 'filter',
      event_ids: selected,
      filters: f,
      max_rows: undefined,
    })
    setPreview(null)
    setRoleSel('supervised')
    trainForm.setFieldsValue({
      role: 'supervised',
      label: 1,
      name: `事件数据集 ${new Date().toLocaleString()}`,
      source_note: '',
    })
    setTrainOpen(true)
  }

  const doPreview = useCallback(
    async (next: SelectionValue = sel) => {
      const body: any = { mode: next.mode }
      if (next.mode === 'ids') {
        if (!selected.length) {
          message.warning('先勾选事件，或改用「按条件筛选」')
          return
        }
        body.event_ids = selected
      } else {
        const f = compactFilters(next.filters)
        if (!Object.keys(f).length) {
          message.warning('至少填一个筛选条件')
          return
        }
        body.filters = f
      }
      if (next.max_rows) body.max_rows = next.max_rows
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
    [sel, selected],
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
      mode: sel.mode,
    }
    if (sel.mode === 'ids') {
      if (!selected.length) {
        message.warning('还没有勾选事件')
        return
      }
      body.event_ids = selected
    } else {
      const f = compactFilters(sel.filters)
      if (!Object.keys(f).length) {
        message.warning('至少填一个筛选条件')
        return
      }
      body.filters = f
    }
    if (sel.max_rows) body.max_rows = sel.max_rows
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

  /** 按当前筛选把匹配的事件全部选中（后端上限 5000；表头全选只覆盖当前页）。 */
  const selectAllMatching = async () => {
    const f = buildFilters()
    if (!Object.keys(f).length) {
      message.warning('先设置至少一个筛选条件（否则会选中整个事件库）')
      return
    }
    setSelecting(true)
    try {
      const p = new URLSearchParams()
      Object.entries(f).forEach(([k, v]) => {
        if (v !== undefined && v !== null && v !== '') p.set(k, String(v))
      })
      const r = await api<any>(`/api/events/ids?${p.toString()}`)
      const ids = r.ids || []
      setSelected(ids)
      message.success(
        r.truncated
          ? `匹配超过 ${r.limit} 条，已选中前 ${ids.length} 条（按时间倒序）`
          : `已选中 ${ids.length} 条匹配事件（可跨页保留）`,
      )
    } catch (e: any) {
      message.error(e?.message || '选中失败')
    } finally {
      setSelecting(false)
    }
  }

  /** 清空游标栈并回第一页：筛选/页大小一变就必须走这里，否则会带着旧筛选的游标翻页。 */
  const resetPaging = useCallback(() => {
    cursorsRef.current = [null]
    setPage(1)
    setTotal(null)
    setHasMore(false)
  }, [])

  /** 提交一份新的文本筛选（防抖到点 / 手动点查询）。 */
  const commitFilters = useCallback(
    (next: Filters) => {
      resetPaging()
      setApplied(next)
    },
    [resetPaging],
  )

  /** 立即生效的筛选（下拉 / 开关 / 页大小）。 */
  const applyNow = (fn: () => void) => {
    resetPaging()
    fn()
  }

  // 草稿与已应用不一致时，400ms 后整体提交：输入过程中不发请求。
  const dirty = JSON.stringify(draft) !== JSON.stringify(applied)
  useEffect(() => {
    if (!dirty) return
    const t = setTimeout(() => commitFilters(draft), 400)
    return () => clearTimeout(t)
    // draft 变才需要重排定时器；applied 由 commit 写入，不必再触发。
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [draft, dirty, commitFilters])

  const load = useCallback(
    async (silent = false) => {
      // 静默轮询不与用户操作抢：已有请求在飞就等下一轮。
      if (silent && inflight.current > 0) return
      const seq = ++reqSeq.current
      inflight.current += 1
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
        // 高级筛选先落，工具栏的显式选择再覆盖它（与 buildFilters 保持一致）。
        Object.entries(advanced).forEach(([k, v]) => {
          if (v === undefined || v === null || v === '') return
          p.set(k, String(v))
        })
        if (action) p.set('action', action)
        if (applied.srcIp) p.set('src_ip', applied.srcIp)
        if (applied.path) p.set('path', applied.path)
        if (applied.q) p.set('q', applied.q)
        if (applied.minScore !== undefined && applied.minScore !== null) {
          p.set('min_score', String(applied.minScore))
        }
        if (onlyTesting) p.set('rule_testing', '1')
        const r = await api<any>(`/api/events?${p.toString()}`)
        // 乱序响应直接丢弃：否则旧筛选/旧页的结果会覆盖新结果（表现为重复行/漏行）。
        if (seq !== reqSeq.current) return
        setRows(r.items || [])
        if (typeof r.total === 'number') setTotal(r.total)
        setHasMore(!!r.has_more)
        // 只有「已展示的这一页」才能写下一页游标。
        if (r.next_cursor) cursorsRef.current[page] = r.next_cursor
        setLastLoaded(Date.now())
      } catch (e: any) {
        if (seq === reqSeq.current) setErr(e?.message || '加载失败')
      } finally {
        inflight.current -= 1
        if (!silent && seq === reqSeq.current) setLoading(false)
      }
    },
    [page, pageSize, applied, action, onlyTesting, advanced, refreshTick],
  )

  /** 入库状态：第一页 / 手动刷新时才拉，30s 内复用（避免反复 COUNT(*)）。 */
  const loadIngest = useCallback(async (force = false) => {
    const now = Date.now()
    if (!force && now - ingestAt.current < 30000) return
    ingestAt.current = now
    try {
      setIngest(await api<any>('/api/ingest/state'))
    } catch {
      /* 状态行失败不影响列表 */
    }
  }, [])

  useEffect(() => {
    load()
    if (page === 1) loadIngest()
  }, [load, page, loadIngest])

  // 规则下拉：事件里实际命中的规则（带命中数），只拉一次。
  useEffect(() => {
    api<any>('/api/events/rule-facets?limit=500')
      .then((r) => setRuleOptions(r.items || []))
      .catch(() => {
        /* 下拉拿不到规则不影响事件列表 */
      })
  }, [])

  // 自动刷新：0 = 关闭；页面隐藏时跳过轮询。
  useEffect(() => {
    if (refreshSec <= 0) return
    const id = setInterval(() => {
      if (document.hidden) return
      load(true)
    }, refreshSec * 1000)
    return () => clearInterval(id)
  }, [refreshSec, load])

  // 回到前台补拉一次（不改变定时策略）。
  useEffect(() => {
    if (refreshSec <= 0) return
    const onVisible = () => {
      if (!document.hidden) load(true)
    }
    document.addEventListener('visibilitychange', onVisible)
    return () => document.removeEventListener('visibilitychange', onVisible)
  }, [refreshSec, load])

  useEffect(() => {
    try {
      localStorage.setItem(REFRESH_KEY, String(refreshSec))
    } catch {
      /* ignore */
    }
  }, [refreshSec])

  const manualRefresh = () => {
    setRefreshTick((v) => v + 1)
    loadIngest(true)
  }

  /** 「查询」/ 回车：跳过防抖立刻提交当前草稿。 */
  const submitNow = () => {
    commitFilters(draft)
    setRefreshTick((v) => v + 1)
    loadIngest(true)
  }

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
          onChange={(v) => applyNow(() => setAction(v))}
          options={[
            { value: 'block', label: 'block' },
            { value: 'alert', label: 'alert' },
            { value: 'allow', label: 'allow' },
          ]}
        />
        <Input
          placeholder="源 IP"
          style={{ width: 150 }}
          value={draft.srcIp}
          onChange={(e) => setDraft((d) => ({ ...d, srcIp: e.target.value }))}
          onPressEnter={submitNow}
        />
        <Input
          placeholder="路径包含"
          style={{ width: 180 }}
          value={draft.path}
          onChange={(e) => setDraft((d) => ({ ...d, path: e.target.value }))}
          onPressEnter={submitNow}
        />
        <Input
          placeholder="关键字（路径/查询/UA）"
          style={{ width: 200 }}
          value={draft.q}
          onChange={(e) => setDraft((d) => ({ ...d, q: e.target.value }))}
          onPressEnter={submitNow}
        />
        <InputNumber
          placeholder="最小监督分"
          min={0}
          max={1}
          step={0.1}
          style={{ width: 140 }}
          value={draft.minScore}
          onChange={(v) =>
            setDraft((d) => ({ ...d, minScore: v === null ? undefined : Number(v) }))
          }
        />
        <Tooltip title="只看命中了「未合格、测试中」规则的事件（rule_testing=1）">
          <Space size={4}>
            <Switch
              size="small"
              checked={onlyTesting}
              onChange={(v) => applyNow(() => setOnlyTesting(v))}
            />
            <span className="muted">只看测试命中</span>
          </Space>
        </Tooltip>
        <Popover
          trigger="click"
          open={advOpen}
          placement="bottomLeft"
          onOpenChange={(o) => {
            setAdvOpen(o)
            if (o) setAdvDraft(advanced)
          }}
          content={
            <div style={{ width: 'min(560px, calc(100vw - 340px))', maxHeight: '70vh', overflowY: 'auto' }}>
              <SelectionBuilder
                value={{ mode: 'filter', filters: advDraft }}
                onChange={(v) => setAdvDraft(v.filters)}
                selectedCount={0}
                showScope={false}
                showMaxRows={false}
                ruleOptions={ruleOptions}
              />
              <Space style={{ marginTop: 8 }}>
                <Button
                  type="primary"
                  onClick={() => {
                    setAdvanced(compactFilters(advDraft))
                    setAdvOpen(false)
                    resetPaging()
                    setRefreshTick((v) => v + 1)
                  }}
                >
                  应用筛选
                </Button>
                <Button
                  onClick={() => {
                    setAdvDraft({})
                    setAdvanced({})
                    setAdvOpen(false)
                    resetPaging()
                    setRefreshTick((v) => v + 1)
                  }}
                >
                  重置
                </Button>
              </Space>
            </div>
          }
        >
          <Button icon={<FilterOutlined />}>
            更多筛选{nAdvanced ? `（${nAdvanced}）` : ''}
          </Button>
        </Popover>
        <Button icon={<SearchOutlined />} type="primary" onClick={submitNow}>
          查询
        </Button>
        <Button icon={<ReloadOutlined />} onClick={manualRefresh}>
          刷新
        </Button>
        <Tooltip title="按当前筛选把匹配事件全部选中（≤5000；表头全选只覆盖当前页）">
          <Button icon={<SearchOutlined />} loading={selecting} onClick={selectAllMatching}>
            选中筛选结果
          </Button>
        </Tooltip>
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
        <Select
          style={{ width: 170 }}
          value={customRefresh ? -1 : refreshSec}
          onChange={(v) => {
            if (v === -1) {
              setCustomRefresh(true)
              if (refreshSec <= 0) setRefreshSec(15)
            } else {
              setCustomRefresh(false)
              setRefreshSec(Number(v))
            }
          }}
          options={[
            { value: 0, label: '自动刷新：关闭' },
            { value: 5, label: '自动刷新：5s' },
            { value: 10, label: '自动刷新：10s' },
            { value: 15, label: '自动刷新：15s' },
            { value: 30, label: '自动刷新：30s' },
            { value: 60, label: '自动刷新：60s' },
            { value: -1, label: '自定义…' },
          ]}
        />
        {customRefresh ? (
          <InputNumber
            min={3}
            max={3600}
            value={refreshSec || 15}
            onChange={(v) => {
              if (v !== null && v !== undefined) setRefreshSec(Number(v))
            }}
            addonAfter="秒"
            style={{ width: 130 }}
          />
        ) : null}
        {dirty ? <span className="muted">筛选输入中…（400ms 后自动查询）</span> : null}
      </div>

      {err ? <Alert type="error" message={err} showIcon style={{ marginBottom: 12 }} /> : null}

      <Card size="small">
        <Table<EventRow>
          size="small"
          rowKey="id"
          loading={loading}
          dataSource={rows}
          // 列宽合计 ≈ 1400：不给横向滚动就会把「路径」挤成 0 宽（table-layout:fixed）。
          scroll={{ x: 1410 }}
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
            {
              title: '路径',
              dataIndex: 'path',
              width: 280,
              ellipsis: { showTitle: false },
              render: (v: string, r: EventRow) =>
                v ? (
                  <Tooltip title={r.query ? `${v}?${r.query}` : v} placement="topLeft">
                    <span>{v}</span>
                  </Tooltip>
                ) : (
                  <span className="muted">-</span>
                ),
            },
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
      </Card>

      <Space style={{ marginTop: 12 }} wrap>
        <Button
          size="small"
          disabled={page <= 1 || loading}
          onClick={() => setPage(page - 1)}
        >
          上一页
        </Button>
        <span className="muted">第 {page} 页</span>
        <Button
          size="small"
          disabled={!hasMore || loading}
          onClick={() => setPage(page + 1)}
        >
          下一页
        </Button>
        <Select
          size="small"
          value={pageSize}
          style={{ width: 110 }}
          onChange={(v) => applyNow(() => setPageSize(v))}
          options={[
            { value: 20, label: '20 条/页' },
            { value: 50, label: '50 条/页' },
            { value: 100, label: '100 条/页' },
            { value: 200, label: '200 条/页' },
          ]}
        />
      </Space>

      <div className="muted" style={{ marginTop: 8, fontSize: 12 }}>
        {total === null ? '按时间倒序 · 游标翻页 · 统计中…' : `共 ${total} 条（第一页统计）`}
        {` · 本页 ${rows.length} 条`}
        {` · 列表已更新 ${lastLoaded ? new Date(lastLoaded).toLocaleTimeString() : '—'}`}
        {ingest ? ` · 最后事件 ${lagText(ingest.lag_sec)}（库内共 ${ingest.n_events ?? '-'} 条）` : ''}
        {refreshSec > 0 ? ` · 自动刷新 ${refreshSec}s` : ' · 自动刷新已关闭'}
      </div>

      <Modal
        open={trainOpen}
        width={760}
        title="从事件生成训练数据集"
        onCancel={() => setTrainOpen(false)}
        styles={{ body: { maxHeight: '62vh', overflowY: 'auto', paddingRight: 4 } }}
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
          <SelectionBuilder
            value={sel}
            onChange={(v) => {
              setSel(v)
              setPreview(null)
            }}
            selectedCount={selected.length}
            ruleOptions={ruleOptions}
          />
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
