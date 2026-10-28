import { useCallback, useEffect, useState } from 'react'
import {
  Alert,
  Button,
  Input,
  InputNumber,
  Select,
  Space,
  Switch,
  Table,
  Tag,
  Tooltip,
  Typography,
} from 'antd'
import { ReloadOutlined, SearchOutlined } from '@ant-design/icons'
import { api, fmtNum, fmtTs } from '../api'
import type { EventRow, User } from '../types'
import EventDetailDrawer, { ActionTag } from '../components/EventDetailDrawer'

const { Title, Text } = Typography

export default function Events({ user }: { user: User }) {
  const [rows, setRows] = useState<EventRow[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(50)
  const [loading, setLoading] = useState(false)
  const [err, setErr] = useState('')

  const [action, setAction] = useState<string | undefined>(undefined)
  const [srcIp, setSrcIp] = useState('')
  const [path, setPath] = useState('')
  const [q, setQ] = useState('')
  const [minScore, setMinScore] = useState<number | undefined>(undefined)
  const [onlyTesting, setOnlyTesting] = useState(false)

  const [detailId, setDetailId] = useState<number | null>(null)

  const load = useCallback(async (silent = false) => {
    if (!silent) setLoading(true)
    setErr('')
    try {
      const p = new URLSearchParams()
      p.set('limit', String(pageSize))
      p.set('offset', String((page - 1) * pageSize))
      if (action) p.set('action', action)
      if (srcIp) p.set('src_ip', srcIp)
      if (path) p.set('path', path)
      if (q) p.set('q', q)
      if (minScore !== undefined && minScore !== null) p.set('min_score', String(minScore))
      if (onlyTesting) p.set('rule_testing', '1')
      const r = await api<any>(`/api/events?${p.toString()}`)
      setRows(r.items || [])
      setTotal(r.total || 0)
    } catch (e: any) {
      setErr(e?.message || '加载失败')
    } finally {
      if (!silent) setLoading(false)
    }
  }, [page, pageSize, action, srcIp, path, q, minScore, onlyTesting])

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
            setPage(1)
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
            setPage(1)
            load()
          }}
        />
        <Input
          placeholder="路径包含"
          style={{ width: 180 }}
          value={path}
          onChange={(e) => setPath(e.target.value)}
          onPressEnter={() => {
            setPage(1)
            load()
          }}
        />
        <Input
          placeholder="关键字（路径/查询/UA）"
          style={{ width: 200 }}
          value={q}
          onChange={(e) => setQ(e.target.value)}
          onPressEnter={() => {
            setPage(1)
            load()
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
                setPage(1)
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
            setPage(1)
            load()
          }}
        >
          查询
        </Button>
        <Button icon={<ReloadOutlined />} onClick={() => load()}>
          刷新
        </Button>
        <span className="muted">自动刷新 15s</span>
      </div>

      {err ? <Alert type="error" message={err} showIcon style={{ marginBottom: 12 }} /> : null}

      <Table<EventRow>
        size="small"
        rowKey="id"
        loading={loading}
        dataSource={rows}
        onRow={(r) => ({ onClick: () => setDetailId(r.id), style: { cursor: 'pointer' } })}
        pagination={{
          current: page,
          pageSize,
          total,
          showSizeChanger: true,
          pageSizeOptions: ['20', '50', '100', '200'],
          onChange: (p, ps) => {
            setPage(p)
            setPageSize(ps)
          },
          showTotal: (n) => `共 ${n} 条`,
        }}
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

      <EventDetailDrawer
        eventId={detailId}
        onClose={() => setDetailId(null)}
        onSelect={setDetailId}
        user={user}
      />
    </div>
  )
}
