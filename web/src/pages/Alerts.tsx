import { useCallback, useEffect, useMemo, useState } from 'react'
import dayjs from 'dayjs'
import {
  Alert,
  Button,
  Card,
  DatePicker,
  Descriptions,
  Drawer,
  Input,
  InputNumber,
  Select,
  Space,
  Switch,
  Table,
  Tabs,
  Tag,
  Tooltip,
  Typography,
  message,
} from 'antd'
import { ReloadOutlined, SearchOutlined } from '@ant-design/icons'
import { api, fmtNum, fmtTs } from '../api'
import type { User } from '../types'
import EventDetailDrawer from '../components/EventDetailDrawer'

const { Title, Text } = Typography

const STAGE_COLOR: Record<string, string> = {
  exploit: 'red',
  probe: 'orange',
  recon: 'gold',
  normal: 'default',
}

const SEVERITY_COLOR: Record<string, string> = {
  P1: 'red',
  P2: 'orange',
  P3: 'default',
}

const stageLabel = (s: string) =>
  ({ exploit: '利用', probe: '试探', recon: '探测', normal: '正常' } as Record<string, string>)[s] || s

type AlertFilters = {
  q: string
  src_ip: string
  action?: string
  attack_type: string
  method?: string
  host: string
  rule: string
  min_score?: number
  status?: string
  /** 自定义时间范围（毫秒），与 RangePicker 同步持久化。 */
  from_ts?: number
  to_ts?: number
}

const EMPTY_FILTERS: AlertFilters = {
  q: '', src_ip: '', attack_type: '', host: '', rule: '',
}

const FLT_KEY = 'waf_alert_filters'
const REFRESH_KEY = 'waf_alerts_refresh_sec'

function loadFilters(): AlertFilters {
  try {
    const raw = localStorage.getItem(FLT_KEY)
    return raw ? { ...EMPTY_FILTERS, ...JSON.parse(raw) } : { ...EMPTY_FILTERS }
  } catch {
    return { ...EMPTY_FILTERS }
  }
}

const REFRESH_PRESETS = [0, 5, 10, 15, 30, 60]

function loadRefresh(): number {
  const raw = localStorage.getItem(REFRESH_KEY)
  const n = raw === null ? 15 : Number(raw)
  if (n === 0) return 0
  return Number.isFinite(n) && n >= 3 && n <= 3600 ? n : 15
}

function loadRange(): [any, any] | null {
  const f = loadFilters()
  if (typeof f.from_ts !== 'number' || typeof f.to_ts !== 'number') return null
  return [dayjs(f.from_ts), dayjs(f.to_ts)]
}

export default function Alerts({ user }: { user: User }) {
  const canWrite = user.role !== 'viewer'
  const [tab, setTab] = useState<'groups' | 'chains'>('groups')

  // ---- 聚合告警 -----------------------------------------------------------
  const [hours, setHours] = useState(24)
  const [bucket, setBucket] = useState(10)

  // ---- 筛选 / 搜索 / 刷新（两个页签共用）----
  const [flt, setFlt] = useState<AlertFilters>(loadFilters)
  const [texts, setTexts] = useState({
    q: flt.q, src_ip: flt.src_ip, attack_type: flt.attack_type,
    host: flt.host, rule: flt.rule,
  })
  const [range, setRange] = useState<[any, any] | null>(loadRange)
  const [refreshSec, setRefreshSec] = useState<number>(loadRefresh)
  const [customRefresh, setCustomRefresh] = useState<boolean>(
    () => !REFRESH_PRESETS.includes(loadRefresh()),
  )
  const [truncated, setTruncated] = useState(false)
  // 同源同类去重：把同一源在同一时间桶内打不同路径的同类攻击合并成一行。
  const [dedup, setDedup] = useState(false)
  // 实体级抑制默认折叠；打开后仍显示，但带「已抑制」标签（只影响可见性）。
  const [includeSuppressed, setIncludeSuppressed] = useState(false)
  const [suppressedHidden, setSuppressedHidden] = useState(0)
  const [items, setItems] = useState<any[]>([])
  const [loading, setLoading] = useState(false)
  const [err, setErr] = useState('')
  const [pageSize, setPageSize] = useState(50)

  // 聚合下钻：「点击查看聚合的流量」
  const [group, setGroup] = useState<any | null>(null)
  // 打开抽屉时的 bucket_min / dedup 快照：防止之后在页面上改窗口导致过滤错配。
  const [gBucketMin, setGBucketMin] = useState(10)
  const [gDedup, setGDedup] = useState(false)
  const [gFrom, setGFrom] = useState<number | null>(null)
  const [gTo, setGTo] = useState<number | null>(null)
  const [gItems, setGItems] = useState<any[]>([])
  const [gTotal, setGTotal] = useState(0)
  const [gPage, setGPage] = useState(1)
  const [gPageSize, setGPageSize] = useState(50)
  const [gLoading, setGLoading] = useState(false)
  const [gErr, setGErr] = useState('')
  const [detailId, setDetailId] = useState<number | null>(null)

  // ---- 攻击链 -------------------------------------------------------------
  const [gapMin, setGapMin] = useState(10)
  const [minEvents, setMinEvents] = useState(2)
  const [includeNoise, setIncludeNoise] = useState(false)
  const [chainIncludeSuppressed, setChainIncludeSuppressed] = useState(false)
  const [chains, setChains] = useState<any[]>([])
  const [chainInfo, setChainInfo] = useState<any>({})
  const [chainLoading, setChainLoading] = useState(false)
  const [chainErr, setChainErr] = useState('')
  const [chainPageSize, setChainPageSize] = useState(50)

  const [chain, setChain] = useState<any | null>(null)
  const [cItems, setCItems] = useState<any[]>([])
  const [cTotal, setCTotal] = useState(0)
  const [cPage, setCPage] = useState(1)
  const [cPageSize, setCPageSize] = useState(50)
  const [cLoading, setCLoading] = useState(false)
  const [cErr, setCErr] = useState('')

  // 文本筛选 400ms 防抖；下拉/数字/时间范围即时生效。
  useEffect(() => {
    const t = setTimeout(() => {
      setFlt((f) => {
        if (
          f.q === texts.q && f.src_ip === texts.src_ip &&
          f.attack_type === texts.attack_type && f.host === texts.host &&
          f.rule === texts.rule
        ) {
          return f
        }
        return {
          ...f, q: texts.q, src_ip: texts.src_ip,
          attack_type: texts.attack_type, host: texts.host, rule: texts.rule,
        }
      })
    }, 400)
    return () => clearTimeout(t)
  }, [texts])

  useEffect(() => {
    try {
      localStorage.setItem(FLT_KEY, JSON.stringify(flt))
    } catch {
      /* ignore */
    }
  }, [flt])
  useEffect(() => {
    try {
      localStorage.setItem(REFRESH_KEY, String(refreshSec))
    } catch {
      /* ignore */
    }
  }, [refreshSec])

  const buildQuery = useCallback(() => {
    const p = new URLSearchParams()
    p.set('window_hours', String(hours))
    if (range) {
      p.set('from_ts', String(range[0].valueOf()))
      p.set('to_ts', String(range[1].valueOf()))
    }
    if (flt.q) p.set('q', flt.q)
    if (flt.src_ip) p.set('src_ip', flt.src_ip)
    if (flt.action) p.set('action', flt.action)
    if (flt.attack_type) p.set('attack_type', flt.attack_type)
    if (flt.method) p.set('method', flt.method)
    if (flt.host) p.set('host', flt.host)
    if (flt.rule) p.set('rule', flt.rule)
    if (flt.min_score !== undefined) p.set('min_score', String(flt.min_score))
    if (flt.status) p.set('status', flt.status)
    return p
  }, [hours, range, flt])

  const load = useCallback(
    async (silent = false) => {
      if (!silent) setLoading(true)
      setErr('')
      try {
        const p = buildQuery()
        p.set('bucket_min', String(bucket))
        p.set('dedup', dedup ? '1' : '0')
        p.set('include_suppressed', includeSuppressed ? '1' : '0')
        p.set('limit', '500')
        const r = await api<any>(`/api/alerts?${p.toString()}`)
        setItems(r.items || [])
        setSuppressedHidden(r.suppressed_hidden || 0)
        setTruncated(!!r.truncated)
      } catch (e: any) {
        setErr(e?.message || '加载失败')
      } finally {
        if (!silent) setLoading(false)
      }
    },
    [buildQuery, bucket, dedup, includeSuppressed],
  )

  const loadChains = useCallback(
    async (silent = false) => {
      if (!silent) setChainLoading(true)
      setChainErr('')
      try {
        const p = buildQuery()
        p.set('gap_min', String(gapMin))
        p.set('min_events', String(minEvents))
        p.set('include_noise', includeNoise ? '1' : '0')
        p.set('include_suppressed', chainIncludeSuppressed ? '1' : '0')
        p.set('limit', '500')
        const r = await api<any>(`/api/alerts/chains?${p.toString()}`)
        setChains(r.items || [])
        setChainInfo(r || {})
      } catch (e: any) {
        setChainErr(e?.message || '加载失败')
      } finally {
        if (!silent) setChainLoading(false)
      }
    },
    [buildQuery, gapMin, minEvents, includeNoise, chainIncludeSuppressed],
  )

  useEffect(() => {
    if (tab === 'groups') load()
  }, [load, tab])

  useEffect(() => {
    if (tab === 'chains') loadChains()
  }, [loadChains, tab])

  // 自动刷新：页面隐藏时跳过轮询，回到页面立即补一次。
  useEffect(() => {
    if (refreshSec <= 0) return
    const id = setInterval(() => {
      if (document.hidden) return
      if (tab === 'groups') load(true)
      else loadChains(true)
    }, refreshSec * 1000)
    return () => clearInterval(id)
  }, [refreshSec, tab, load, loadChains])

  useEffect(() => {
    const onVisible = () => {
      if (document.hidden) return
      if (tab === 'groups') load(true)
      else loadChains(true)
    }
    document.addEventListener('visibilitychange', onVisible)
    return () => document.removeEventListener('visibilitychange', onVisible)
  }, [tab, load, loadChains])

  const fetchGroup = async (
    row: any,
    bmin: number,
    page: number,
    psize: number,
    dd: boolean = dedup,
  ) => {
    setGLoading(true)
    setGErr('')
    try {
      const p = new URLSearchParams()
      p.set('src_ip', row.src_ip || '')
      p.set('action', row.action || '')
      p.set('bucket', String(row.bucket))
      p.set('bucket_min', String(bmin))
      if (dd) {
        p.set('dedup', '1')
        p.set('attack_type', row.attack_type || '')
      } else {
        p.set('method', row.method || '')
        p.set('path', row.path || '')
      }
      p.set('limit', String(psize))
      p.set('offset', String((page - 1) * psize))
      const r = await api<any>(`/api/alerts/events?${p.toString()}`)
      setGItems(r.items || [])
      setGTotal(r.total || 0)
      setGFrom(r.from_ts ?? null)
      setGTo(r.to_ts ?? null)
    } catch (e: any) {
      setGErr(e?.message || '加载失败')
    } finally {
      setGLoading(false)
    }
  }

  const openGroup = (row: any) => {
    setGroup(row)
    setGBucketMin(bucket)
    setGDedup(dedup)
    setGPage(1)
    setGPageSize(50)
    setDetailId(null)
    fetchGroup(row, bucket, 1, 50, dedup)
  }

  const closeGroup = () => {
    setGroup(null)
    setGItems([])
    setGTotal(0)
    setGErr('')
    setGFrom(null)
    setGTo(null)
    setDetailId(null)
  }

  const fetchChain = async (row: any, page: number, psize: number) => {
    setCLoading(true)
    setCErr('')
    try {
      const p = new URLSearchParams()
      p.set('src_ip', row.src_ip || '')
      if (row.ua) p.set('ua', row.ua)
      p.set('from_ts', String(row.first_ts))
      p.set('to_ts', String(row.last_ts))
      p.set('limit', String(psize))
      p.set('offset', String((page - 1) * psize))
      const r = await api<any>(`/api/alerts/chains/events?${p.toString()}`)
      setCItems(r.items || [])
      setCTotal(r.total || 0)
    } catch (e: any) {
      setCErr(e?.message || '加载失败')
    } finally {
      setCLoading(false)
    }
  }

  const openChain = (row: any) => {
    setChain(row)
    setCPage(1)
    setCPageSize(50)
    setDetailId(null)
    fetchChain(row, 1, 50)
  }

  const closeChain = () => {
    setChain(null)
    setCItems([])
    setCTotal(0)
    setCErr('')
    setDetailId(null)
  }

  const ack = async (row: any, status: string, key: 'group_key' | 'chain_key') => {
    try {
      await api('/api/alerts/ack', {
        method: 'POST',
        body: { group_key: row[key], status, assignee: user.username },
      })
      message.success('已更新')
      if (key === 'group_key') {
        load()
        if (group && group.group_key === row.group_key) setGroup({ ...group, status })
      } else {
        loadChains(true)
        if (chain && chain.chain_key === row.chain_key) setChain({ ...chain, status })
      }
    } catch (e: any) {
      message.error(e?.message || '更新失败')
    }
  }

  const filterCount = useMemo(() => {
    let n = 0
    for (const k of ['q', 'src_ip', 'action', 'attack_type', 'method', 'host', 'rule'] as const) {
      if ((flt as any)[k]) n += 1
    }
    if (flt.min_score !== undefined) n += 1
    if (flt.status) n += 1
    if (range) n += 1
    return n
  }, [flt, range])

  const statusTag = (v: string) => (
    <Tag color={v === 'open' ? 'default' : v === 'closed' ? 'green' : 'blue'}>{v}</Tag>
  )

  const suppressionTag = (r: any) =>
    r.suppression ? (
      <Tooltip
        title={`${r.suppression.reason}（审批 ${r.suppression.approved_by || '-'}，到期 ${fmtTs(
          r.suppression.expires_at,
        )}）`}
      >
        <Tag color="purple">已抑制</Tag>
      </Tooltip>
    ) : (
      <span className="muted">-</span>
    )

  const actionButtons = (row: any, key: 'group_key' | 'chain_key') =>
    canWrite ? (
      <Space>
        <Button
          size="small"
          onClick={(e) => {
            e.stopPropagation()
            ack(row, 'ack', key)
          }}
        >
          确认
        </Button>
        <Button
          size="small"
          onClick={(e) => {
            e.stopPropagation()
            ack(row, 'closed', key)
          }}
        >
          关闭
        </Button>
      </Space>
    ) : (
      <span className="muted">只读</span>
    )

  const groupsTab = (
    <>
      <div className="toolbar">
        <span className="muted">聚合窗口（分钟）</span>
        <InputNumber min={1} max={1440} value={bucket} onChange={(v) => setBucket(Number(v || 10))} />
        <span className="muted">同源同类去重</span>
        <Switch checked={dedup} onChange={setDedup} />
        <span className="muted">显示已抑制</span>
        <Switch checked={includeSuppressed} onChange={setIncludeSuppressed} />
        <Button icon={<ReloadOutlined />} onClick={() => load()}>
          刷新
        </Button>
        <span className="muted">
          自动刷新 {refreshSec > 0 ? `${refreshSec}s` : '已关闭'}
        </span>
      </div>

      <Alert
        type="info"
        showIcon
        style={{ marginBottom: 12 }}
        message={
          dedup
            ? '已开启去重：按「源 IP + 动作 + 攻击类型 + 时间桶」合并，同一源在同一桶内打不同路径的同类攻击只占一行（看「路径数」）。点击行查看该合并组的全部原始流量。'
            : '按「源 IP + 动作 + 方法/路径 + 时间桶」聚合；点击任意行查看该聚合组的原始流量。扫描风暴刷屏时可打开「同源同类去重」。'
        }
        description={
          suppressedHidden
            ? `另有 ${suppressedHidden} 组被实体级抑制折叠（只影响控制台可见性，数据面仍照常拦截/告警；打开上方开关查看）。`
            : undefined
        }
      />
      {truncated ? (
        <Alert
          type="warning"
          showIcon
          style={{ marginBottom: 12 }}
          message="结果超过 500 条已截断：请缩小时间窗口或增加筛选条件。"
        />
      ) : null}
      {err ? <Alert type="error" message={err} showIcon style={{ marginBottom: 12 }} /> : null}

      <Card size="small">
        <Table
          size="small"
          rowKey="group_key"
          loading={loading}
          dataSource={items}
          onRow={(r) => ({
            onClick: () => openGroup(r),
            style: { cursor: 'pointer', opacity: r.suppression ? 0.55 : 1 }
          })}
          pagination={{
            pageSize,
            showSizeChanger: true,
            pageSizeOptions: ['20', '50', '100', '200'],
            onShowSizeChange: (_p, ps) => setPageSize(ps),
            showTotal: (n) => `共 ${n} 组`,
          }}
          columns={[
            {
              title: '级别',
              dataIndex: 'severity',
              width: 76,
              render: (v: string) => <Tag color={v === 'P1' ? 'red' : 'orange'}>{v}</Tag>,
            },
            { title: '源 IP', dataIndex: 'src_ip', width: 130 },
            {
              title: '动作',
              dataIndex: 'action',
              width: 84,
              render: (v: string) => <Tag color={v === 'block' ? 'red' : 'orange'}>{v}</Tag>,
            },
            ...(dedup
              ? [
                  {
                    title: '攻击类型',
                    dataIndex: 'attack_type',
                    width: 140,
                    render: (v: string | null) =>
                      v ? <Tag color="volcano">{v}</Tag> : <span className="muted">未分类</span>,
                  },
                ]
              : [
                  {
                    title: '方法 / 路径',
                    width: 280,
                    render: (_: any, r: any) => (
                      <span>
                        <Tag>{r.method}</Tag>
                        <Text code>{r.path}</Text>
                      </span>
                    ),
                  },
                ]),
            { title: '次数', dataIndex: 'n', width: 80, align: 'right' },
            ...(dedup ? [{ title: '路径数', dataIndex: 'path_count', width: 90, align: 'right' }] : []),
            {
              title: '最高监督分',
              dataIndex: 'max_score',
              width: 120,
              render: (v: number) => fmtNum(v, 4),
            },
            { title: '类型', dataIndex: 'attack_type', width: 100 },
            { title: '首次', dataIndex: 'first_ts', width: 165, render: (v) => fmtTs(v) },
            { title: '最近', dataIndex: 'last_ts', width: 165, render: (v) => fmtTs(v) },
            {
              title: '状态',
              dataIndex: 'status',
              width: 90,
              render: (v: string) => statusTag(v),
            },
            {
              title: '抑制',
              width: 90,
              render: (_: any, r: any) => suppressionTag(r),
            },
            {
              title: '操作',
              width: 190,
              render: (_: any, r: any) => actionButtons(r, 'group_key'),
            },
          ] as any[]}
        />
      </Card>
    </>
  )

  const chainsTab = (
    <>
      <div className="toolbar">
        <span className="muted">切链间隔（分钟）</span>
        <InputNumber min={1} max={1440} value={gapMin} onChange={(v) => setGapMin(Number(v || 10))} />
        <span className="muted">最少事件</span>
        <InputNumber min={1} max={1000} value={minEvents} onChange={(v) => setMinEvents(Number(v || 2))} />
        <span className="muted">显示扫描噪音</span>
        <Switch checked={includeNoise} onChange={setIncludeNoise} />
        <span className="muted">显示已抑制</span>
        <Switch checked={chainIncludeSuppressed} onChange={setChainIncludeSuppressed} />
        <Button icon={<ReloadOutlined />} onClick={() => loadChains()}>
          刷新
        </Button>
        <span className="muted">
          自动刷新 {refreshSec > 0 ? `${refreshSec}s` : '已关闭'}
        </span>
      </div>

      <Alert
        type="info"
        showIcon
        style={{ marginBottom: 12 }}
        message="按「源 IP + UA」聚合窗口内事件，间隔超过切链阈值就分成新链；阶段按拦截→利用 / 告警→试探 / 失败请求→探测归类。大量探测且无拦截的扫描噪音默认折叠。"
        description={
          chainInfo?.noise_hidden || chainInfo?.suppressed_hidden ? (
            <span>
              {chainInfo?.noise_hidden
                ? `另有 ${chainInfo.noise_hidden} 条扫描噪音链已折叠（打开上方开关查看）。`
                : null}
              {chainInfo?.noise_hidden && chainInfo?.suppressed_hidden ? ' ' : null}
              {chainInfo?.suppressed_hidden
                ? `另有 ${chainInfo.suppressed_hidden} 条链被实体级抑制折叠（只影响可见性，数据面照常判定）。`
                : null}
            </span>
          ) : undefined
        }
      />
      {chainInfo?.truncated ? (
        <Alert
          type="warning"
          showIcon
          style={{ marginBottom: 12 }}
          message={`本次取数达到上限（${chainInfo.scanned_rows} 行 / ${chainInfo.scanned_sources} 个源），结果可能不完整，请缩小时间窗口。`}
        />
      ) : null}
      {chainErr ? <Alert type="error" message={chainErr} showIcon style={{ marginBottom: 12 }} /> : null}

      <Card size="small">
        <Table
          size="small"
          rowKey="chain_key"
          loading={chainLoading}
          dataSource={chains}
          onRow={(r) => ({
            onClick: () => openChain(r),
            style: { cursor: 'pointer', opacity: r.suppression ? 0.55 : 1 },
          })}
          pagination={{
            pageSize: chainPageSize,
            showSizeChanger: true,
            pageSizeOptions: ['20', '50', '100', '200'],
            onShowSizeChange: (_p, ps) => setChainPageSize(ps),
            showTotal: (n) => `共 ${n} 条链`,
          }}
          columns={[
            {
              title: '级别',
              dataIndex: 'severity',
              width: 76,
              render: (v: string) => <Tag color={SEVERITY_COLOR[v] || 'default'}>{v}</Tag>,
            },
            { title: '源 IP', dataIndex: 'src_ip', width: 130 },
            {
              title: 'UA',
              dataIndex: 'ua',
              width: 180,
              ellipsis: true,
              render: (v: string | null) =>
                v ? (
                  <Tooltip title={v}>
                    <span>{v}</span>
                  </Tooltip>
                ) : (
                  <span className="muted">-</span>
                ),
            },
            {
              title: '阶段',
              dataIndex: 'stages',
              width: 150,
              render: (v: string[] = []) =>
                v.length ? (
                  <Space size={2} wrap>
                    {v.map((s) => (
                      <Tag key={s} color={STAGE_COLOR[s] || 'default'}>
                        {stageLabel(s)}
                      </Tag>
                    ))}
                  </Space>
                ) : (
                  <span className="muted">-</span>
                ),
            },
            { title: '事件数', dataIndex: 'n', width: 80, align: 'right' },
            {
              title: '拦截 / 试探 / 探测',
              width: 130,
              render: (_: any, r: any) => (
                <span>
                  <Text type={r.blocked ? 'danger' : undefined}>{r.blocked}</Text>
                  <span className="muted"> / {r.alerted} / {r.recon}</span>
                </span>
              ),
            },
            {
              title: '最高监督分',
              dataIndex: 'max_score',
              width: 110,
              render: (v: number) => fmtNum(v, 4),
            },
            {
              title: '攻击类型',
              dataIndex: 'attack_types',
              width: 160,
              render: (v: any[] = []) =>
                v.length ? (
                  <Space size={2} wrap>
                    {v.map((a) => (
                      <Tag key={a.attack_type} color="volcano">
                        {a.attack_type} ×{a.n}
                      </Tag>
                    ))}
                  </Space>
                ) : (
                  <span className="muted">-</span>
                ),
            },
            {
              title: '时序命中',
              dataIndex: 'sequences',
              width: 150,
              render: (v: any[] = []) =>
                v.length ? (
                  <Space size={2} wrap>
                    {v.map((s) => (
                      <Tooltip key={s.rule_id} title={`${s.rule_id} · 最近 ${fmtTs(s.last_ts)}`}>
                        <Tag color="geekblue">{s.name}</Tag>
                      </Tooltip>
                    ))}
                  </Space>
                ) : (
                  <span className="muted">-</span>
                ),
            },
            { title: '首次', dataIndex: 'first_ts', width: 165, render: (v) => fmtTs(v) },
            { title: '最近', dataIndex: 'last_ts', width: 165, render: (v) => fmtTs(v) },
            {
              title: '状态',
              dataIndex: 'status',
              width: 90,
              render: (v: string) => statusTag(v),
            },
            {
              title: '抑制',
              width: 90,
              render: (_: any, r: any) => suppressionTag(r),
            },
            {
              title: '操作',
              width: 190,
              render: (_: any, r: any) => actionButtons(r, 'chain_key'),
            },
          ]}
        />
      </Card>
    </>
  )

  return (
    <div>
      <div className="toolbar">
        <Title level={4} className="page-title">
          告警
        </Title>
      </div>

      <Card size="small" style={{ marginBottom: 12 }}>
        <Space wrap>
          <Input
            allowClear
            prefix={<SearchOutlined />}
            placeholder="搜索 IP / 路径 / 类型 / UA / 规则"
            style={{ width: 260 }}
            value={texts.q}
            onChange={(e) => setTexts((t) => ({ ...t, q: e.target.value }))}
            onPressEnter={() => setFlt((f) => ({ ...f, ...texts }))}
          />
          <Input
            allowClear
            placeholder="源 IP"
            style={{ width: 150 }}
            value={texts.src_ip}
            onChange={(e) => setTexts((t) => ({ ...t, src_ip: e.target.value }))}
            onPressEnter={() => setFlt((f) => ({ ...f, ...texts }))}
          />
          <Select
            allowClear
            placeholder="动作"
            style={{ width: 110 }}
            value={flt.action}
            onChange={(v) => setFlt((f) => ({ ...f, action: v }))}
            options={[
              { value: 'block', label: 'block' },
              { value: 'alert', label: 'alert' },
            ]}
          />
          <Input
            allowClear
            placeholder="攻击类型（精确）"
            style={{ width: 150 }}
            value={texts.attack_type}
            onChange={(e) => setTexts((t) => ({ ...t, attack_type: e.target.value }))}
            onPressEnter={() => setFlt((f) => ({ ...f, ...texts }))}
          />
          <Select
            allowClear
            placeholder="方法"
            style={{ width: 115 }}
            value={flt.method}
            onChange={(v) => setFlt((f) => ({ ...f, method: v }))}
            options={['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'].map(
              (m) => ({ value: m, label: m }),
            )}
          />
          <Input
            allowClear
            placeholder="Host"
            style={{ width: 150 }}
            value={texts.host}
            onChange={(e) => setTexts((t) => ({ ...t, host: e.target.value }))}
            onPressEnter={() => setFlt((f) => ({ ...f, ...texts }))}
          />
          <Input
            allowClear
            placeholder="规则 id / 名称"
            style={{ width: 160 }}
            value={texts.rule}
            onChange={(e) => setTexts((t) => ({ ...t, rule: e.target.value }))}
            onPressEnter={() => setFlt((f) => ({ ...f, ...texts }))}
          />
          <InputNumber
            placeholder="最低监督分"
            min={0}
            max={1}
            step={0.1}
            style={{ width: 140 }}
            value={flt.min_score}
            onChange={(v) => setFlt((f) => ({
              ...f, min_score: v === null || v === undefined ? undefined : Number(v),
            }))}
          />
          <Select
            allowClear
            placeholder="状态"
            style={{ width: 115 }}
            value={flt.status}
            onChange={(v) => setFlt((f) => ({ ...f, status: v }))}
            options={[
              { value: 'open', label: '未处理' },
              { value: 'ack', label: '已阅' },
              { value: 'closed', label: '已关闭' },
              { value: 'pending', label: '待定' },
            ]}
          />
          <Select
            value={hours}
            onChange={(v) => {
              setHours(v)
              // 选固定窗口即取消自定义范围，避免两个时间条件同时存在。
              setRange(null)
              setFlt((f) => ({ ...f, from_ts: undefined, to_ts: undefined }))
            }}
            style={{ width: 130 }}
            options={[
              { value: 1, label: '近 1 小时' },
              { value: 6, label: '近 6 小时' },
              { value: 24, label: '近 24 小时' },
              { value: 24 * 7, label: '近 7 天' },
            ]}
          />
          <DatePicker.RangePicker
            showTime
            value={range as any}
            onChange={(v) => {
              const r = v as any
              setRange(r)
              setFlt((f) => ({
                ...f,
                from_ts: r?.[0]?.valueOf(),
                to_ts: r?.[1]?.valueOf(),
              }))
            }}
          />
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
          <Button
            onClick={() => {
              setTexts({ q: '', src_ip: '', attack_type: '', host: '', rule: '' })
              setFlt({ ...EMPTY_FILTERS })
              setRange(null)
            }}
          >
            重置筛选
          </Button>
          <span className="muted">筛选 {filterCount} 项</span>
        </Space>
      </Card>

      <Tabs
        activeKey={tab}
        onChange={(k) => setTab(k as 'groups' | 'chains')}
        items={[
          { key: 'groups', label: '聚合告警', children: groupsTab },
          { key: 'chains', label: '攻击链', children: chainsTab },
        ]}
      />

      <Drawer
        width={980}
        open={!!group}
        onClose={closeGroup}
        title={group ? `聚合流量 · ${group.src_ip} · ${group.action}` : ''}
        extra={
          <Button
            size="small"
            icon={<ReloadOutlined />}
            onClick={() => group && fetchGroup(group, gBucketMin, gPage, gPageSize, gDedup)}
          >
            刷新
          </Button>
        }
      >
        {group ? (
          <>
            <Descriptions
              size="small"
              bordered
              column={2}
              items={[
                { key: 'ip', label: '源 IP', children: group.src_ip },
                {
                  key: 'act',
                  label: '动作',
                  children: (
                    <Tag color={group.action === 'block' ? 'red' : 'orange'}>{group.action}</Tag>
                  ),
                },
                {
                  key: 'mp',
                  label: gDedup ? '攻击类型' : '方法 / 路径',
                  children: gDedup ? (
                    group.attack_type ? (
                      <Tag color="volcano">{group.attack_type}</Tag>
                    ) : (
                      <span className="muted">未分类</span>
                    )
                  ) : (
                    <span>
                      <Tag>{group.method || '-'}</Tag>
                      <Text code>{group.path || '-'}</Text>
                    </span>
                  ),
                },
                { key: 'n', label: '聚合次数', children: group.n },
                ...(gDedup
                  ? [{ key: 'pc', label: '路径数', children: group.path_count }]
                  : []),
                {
                  key: 'win',
                  label: '时间桶',
                  children: gFrom != null && gTo != null ? `${fmtTs(gFrom)} ~ ${fmtTs(gTo)}` : '-',
                },
                { key: 'score', label: '最高监督分', children: fmtNum(group.max_score, 4) },
              ]}
            />
            <div className="muted" style={{ margin: '8px 0' }}>
              {gDedup
                ? '与聚合行完全一致的精确过滤（同源 IP、动作、攻击类型、时间桶）；点击事件行查看完整详情。'
                : '与聚合行完全一致的精确过滤（同源 IP、动作、方法/路径、时间桶）；点击事件行查看完整详情（取证包 / SHAP / 反馈）。'}
            </div>
            {gErr ? <Alert type="error" message={gErr} showIcon style={{ marginBottom: 12 }} /> : null}
            <Table
              size="small"
              rowKey="id"
              loading={gLoading}
              dataSource={gItems}
              onRow={(r) => ({ onClick: () => setDetailId(r.id), style: { cursor: 'pointer' } })}
              pagination={{
                current: gPage,
                pageSize: gPageSize,
                total: gTotal,
                showSizeChanger: true,
                pageSizeOptions: ['20', '50', '100', '200'],
                onChange: (p, ps) => {
                  setGPage(p)
                  setGPageSize(ps)
                  if (group) fetchGroup(group, gBucketMin, p, ps, gDedup)
                },
                showTotal: (n) => `共 ${n} 条`,
              }}
              columns={[
                { title: '时间', dataIndex: 'ts', width: 165, render: (v) => fmtTs(v) },
                { title: '状态码', dataIndex: 'status', width: 76, render: (v) => v ?? '-' },
                {
                  title: '动作',
                  dataIndex: 'action',
                  width: 88,
                  render: (v) => <Tag color={v === 'block' ? 'red' : 'orange'}>{v}</Tag>,
                },
                {
                  title: '监督分 / 阈值',
                  width: 150,
                  render: (_: any, r: any) => {
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
                  title: '类型',
                  dataIndex: 'attack_type',
                  width: 100,
                  render: (v: any) =>
                    v ? <Tag color="volcano">{v}</Tag> : <span className="muted">-</span>,
                },
                {
                  title: '规则',
                  width: 90,
                  render: (_: any, r: any) =>
                    r.rule_hits?.length ? (
                      <Tooltip title={r.rule_hits.map((h: any) => h.rule).join('、')}>
                        <Tag
                          color={
                            r.rule_hits.some((h: any) => h.action === 'block') ? 'red' : 'gold'
                          }
                        >
                          {r.rule_hits.length} 条
                        </Tag>
                      </Tooltip>
                    ) : (
                      <span className="muted">-</span>
                    ),
                },
              ]}
            />
          </>
        ) : null}
      </Drawer>

      <Drawer
        width={1080}
        open={!!chain}
        onClose={closeChain}
        title={chain ? `攻击链 · ${chain.src_ip} · ${chain.n} 个事件` : ''}
        extra={
          <Button
            size="small"
            icon={<ReloadOutlined />}
            onClick={() => chain && fetchChain(chain, cPage, cPageSize)}
          >
            刷新
          </Button>
        }
      >
        {chain ? (
          <>
            <Descriptions
              size="small"
              bordered
              column={3}
              items={[
                { key: 'sev', label: '级别', children: <Tag color={SEVERITY_COLOR[chain.severity]}>{chain.severity}</Tag> },
                { key: 'ip', label: '源 IP', children: chain.src_ip },
                {
                  key: 'ua',
                  label: 'User-Agent',
                  children: chain.ua ? (
                    <Tooltip title={chain.ua}>
                      <span>{chain.ua}</span>
                    </Tooltip>
                  ) : (
                    '-'
                  ),
                },
                {
                  key: 'stages',
                  label: '阶段',
                  children: (
                    <Space size={2} wrap>
                      {(chain.stages || []).map((s: string) => (
                        <Tag key={s} color={STAGE_COLOR[s] || 'default'}>
                          {stageLabel(s)}
                        </Tag>
                      ))}
                    </Space>
                  ),
                },
                { key: 'n', label: '事件数', children: chain.n },
                {
                  key: 'counts',
                  label: '拦截 / 试探 / 探测',
                  children: `${chain.blocked} / ${chain.alerted} / ${chain.recon}`,
                },
                { key: 'host', label: '目标 Host', children: (chain.hosts || []).join('、') || '-' },
                { key: 'score', label: '最高监督分', children: fmtNum(chain.max_score, 4) },
                {
                  key: 'seq',
                  label: '时序命中',
                  children: (chain.sequences || []).map((s: any) => s.name).join('、') || '-',
                },
                { key: 'first', label: '首次', children: fmtTs(chain.first_ts) },
                { key: 'last', label: '最近', children: fmtTs(chain.last_ts) },
                { key: 'status', label: '状态', children: statusTag(chain.status) },
              ]}
            />
            {chain.noise ? (
              <Alert
                type="warning"
                showIcon
                style={{ margin: '8px 0' }}
                message="扫描噪音：探测次数多但没有任何拦截，默认折叠；确认/关闭可抑制后续重复提醒。"
              />
            ) : null}
            {chain.top_paths?.length ? (
              <div className="muted" style={{ margin: '8px 0' }}>
                高频路径：
                {chain.top_paths.map((p: any) => (
                  <Tag key={p.path}>
                    {p.path} ×{p.n}
                  </Tag>
                ))}
              </div>
            ) : null}
            {cErr ? <Alert type="error" message={cErr} showIcon style={{ marginBottom: 12 }} /> : null}
            <Table
              size="small"
              rowKey="id"
              loading={cLoading}
              dataSource={cItems}
              onRow={(r) => ({ onClick: () => setDetailId(r.id), style: { cursor: 'pointer' } })}
              pagination={{
                current: cPage,
                pageSize: cPageSize,
                total: cTotal,
                showSizeChanger: true,
                pageSizeOptions: ['20', '50', '100', '200'],
                onChange: (p, ps) => {
                  setCPage(p)
                  setCPageSize(ps)
                  if (chain) fetchChain(chain, p, ps)
                },
                showTotal: (n) => `共 ${n} 条`,
              }}
              columns={[
                { title: '时间', dataIndex: 'ts', width: 165, render: (v) => fmtTs(v) },
                {
                  title: '阶段',
                  dataIndex: 'stage',
                  width: 84,
                  render: (v: string) => <Tag color={STAGE_COLOR[v] || 'default'}>{stageLabel(v)}</Tag>,
                },
                { title: '状态码', dataIndex: 'status', width: 76, render: (v) => v ?? '-' },
                {
                  title: '动作',
                  dataIndex: 'action',
                  width: 88,
                  render: (v) => <Tag color={v === 'block' ? 'red' : v === 'alert' ? 'orange' : 'default'}>{v}</Tag>,
                },
                {
                  title: '方法 / 路径',
                  width: 260,
                  ellipsis: true,
                  render: (_: any, r: any) => (
                    <span>
                      <Tag>{r.method}</Tag>
                      <Text code>{r.path}</Text>
                    </span>
                  ),
                },
                {
                  title: '监督分 / 阈值',
                  width: 150,
                  render: (_: any, r: any) => {
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
                  title: '类型',
                  dataIndex: 'attack_type',
                  width: 100,
                  render: (v: any) =>
                    v ? <Tag color="volcano">{v}</Tag> : <span className="muted">-</span>,
                },
                {
                  title: '规则',
                  width: 90,
                  render: (_: any, r: any) =>
                    r.rule_hits?.length ? (
                      <Tooltip title={r.rule_hits.map((h: any) => h.rule).join('、')}>
                        <Tag
                          color={
                            r.rule_hits.some((h: any) => h.action === 'block') ? 'red' : 'gold'
                          }
                        >
                          {r.rule_hits.length} 条
                        </Tag>
                      </Tooltip>
                    ) : (
                      <span className="muted">-</span>
                    ),
                },
              ]}
            />
          </>
        ) : null}
      </Drawer>

      <EventDetailDrawer
        eventId={detailId}
        onClose={() => setDetailId(null)}
        onSelect={setDetailId}
        user={user}
      />
    </div>
  )
}
