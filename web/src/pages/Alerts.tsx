import { useCallback, useEffect, useState } from 'react'
import {
  Alert,
  Button,
  Card,
  Descriptions,
  Drawer,
  InputNumber,
  Select,
  Space,
  Table,
  Tag,
  Tooltip,
  Typography,
  message,
} from 'antd'
import { ReloadOutlined } from '@ant-design/icons'
import { api, fmtNum, fmtTs } from '../api'
import type { User } from '../types'
import EventDetailDrawer from '../components/EventDetailDrawer'

const { Title, Text } = Typography

export default function Alerts({ user }: { user: User }) {
  const canWrite = user.role !== 'viewer'
  const [hours, setHours] = useState(24)
  const [bucket, setBucket] = useState(10)
  const [items, setItems] = useState<any[]>([])
  const [loading, setLoading] = useState(false)
  const [err, setErr] = useState('')
  const [pageSize, setPageSize] = useState(50)

  // 聚合下钻：「点击查看聚合的流量」
  const [group, setGroup] = useState<any | null>(null)
  // 打开抽屉时的 bucket_min 快照：防止之后在页面上改窗口导致过滤错配。
  const [gBucketMin, setGBucketMin] = useState(10)
  const [gFrom, setGFrom] = useState<number | null>(null)
  const [gTo, setGTo] = useState<number | null>(null)
  const [gItems, setGItems] = useState<any[]>([])
  const [gTotal, setGTotal] = useState(0)
  const [gPage, setGPage] = useState(1)
  const [gPageSize, setGPageSize] = useState(50)
  const [gLoading, setGLoading] = useState(false)
  const [gErr, setGErr] = useState('')
  const [detailId, setDetailId] = useState<number | null>(null)

  const load = useCallback(async (silent = false) => {
    if (!silent) setLoading(true)
    setErr('')
    try {
      const r = await api<any>(`/api/alerts?window_hours=${hours}&bucket_min=${bucket}`)
      setItems(r.items || [])
    } catch (e: any) {
      setErr(e?.message || '加载失败')
    } finally {
      if (!silent) setLoading(false)
    }
  }, [hours, bucket])

  useEffect(() => {
    load()
    const timer = setInterval(() => load(true), 15000)
    return () => clearInterval(timer)
  }, [load])

  const fetchGroup = async (row: any, bmin: number, page: number, psize: number) => {
    setGLoading(true)
    setGErr('')
    try {
      const p = new URLSearchParams()
      p.set('src_ip', row.src_ip || '')
      p.set('action', row.action || '')
      p.set('bucket', String(row.bucket))
      p.set('bucket_min', String(bmin))
      p.set('method', row.method || '')
      p.set('path', row.path || '')
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
    setGPage(1)
    setGPageSize(50)
    setDetailId(null)
    fetchGroup(row, bucket, 1, 50)
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

  const ack = async (row: any, status: string) => {
    try {
      await api('/api/alerts/ack', {
        method: 'POST',
        body: { group_key: row.group_key, status, assignee: user.username },
      })
      message.success('已更新')
      load()
    } catch (e: any) {
      message.error(e?.message || '更新失败')
    }
  }

  return (
    <div>
      <div className="toolbar">
        <Title level={4} className="page-title">
          告警（聚合）
        </Title>
        <Select
          value={hours}
          onChange={setHours}
          style={{ width: 140 }}
          options={[
            { value: 1, label: '近 1 小时' },
            { value: 6, label: '近 6 小时' },
            { value: 24, label: '近 24 小时' },
            { value: 24 * 7, label: '近 7 天' },
          ]}
        />
        <span className="muted">聚合窗口（分钟）</span>
        <InputNumber min={1} max={1440} value={bucket} onChange={(v) => setBucket(Number(v || 10))} />
        <Button icon={<ReloadOutlined />} onClick={() => load()}>
          刷新
        </Button>
        <span className="muted">自动刷新 15s</span>
      </div>

      <Alert
        type="info"
        showIcon
        style={{ marginBottom: 12 }}
        message="按「源 IP + 动作 + 方法/路径 + 时间桶」聚合；点击任意行查看该聚合组的原始流量。攻击链关联尚未实现（见 README 待办）。"
      />
      {err ? <Alert type="error" message={err} showIcon style={{ marginBottom: 12 }} /> : null}

      <Card size="small">
        <Table
          size="small"
          rowKey="group_key"
          loading={loading}
          dataSource={items}
          onRow={(r) => ({ onClick: () => openGroup(r), style: { cursor: 'pointer' } })}
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
            { title: '次数', dataIndex: 'n', width: 80, align: 'right' },
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
              render: (v: string) => (
                <Tag color={v === 'open' ? 'default' : v === 'closed' ? 'green' : 'blue'}>{v}</Tag>
              ),
            },
            {
              title: '操作',
              width: 190,
              render: (_: any, r: any) =>
                canWrite ? (
                  <Space>
                    <Button
                      size="small"
                      onClick={(e) => {
                        e.stopPropagation()
                        ack(r, 'ack')
                      }}
                    >
                      确认
                    </Button>
                    <Button
                      size="small"
                      onClick={(e) => {
                        e.stopPropagation()
                        ack(r, 'closed')
                      }}
                    >
                      关闭
                    </Button>
                  </Space>
                ) : (
                  <span className="muted">只读</span>
                ),
            },
          ]}
        />
      </Card>

      <Drawer
        width={980}
        open={!!group}
        onClose={closeGroup}
        title={group ? `聚合流量 · ${group.src_ip} · ${group.action}` : ''}
        extra={
          <Button
            size="small"
            icon={<ReloadOutlined />}
            onClick={() => group && fetchGroup(group, gBucketMin, gPage, gPageSize)}
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
                  label: '方法 / 路径',
                  children: (
                    <span>
                      <Tag>{group.method || '-'}</Tag>
                      <Text code>{group.path || '-'}</Text>
                    </span>
                  ),
                },
                { key: 'n', label: '聚合次数', children: group.n },
                {
                  key: 'win',
                  label: '时间桶',
                  children: gFrom != null && gTo != null ? `${fmtTs(gFrom)} ~ ${fmtTs(gTo)}` : '-',
                },
                { key: 'score', label: '最高监督分', children: fmtNum(group.max_score, 4) },
              ]}
            />
            <div className="muted" style={{ margin: '8px 0' }}>
              与聚合行完全一致的精确过滤（同源 IP、动作、方法/路径、时间桶）；点击事件行查看完整详情（取证包 /
              SHAP / 反馈）。
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
                  if (group) fetchGroup(group, gBucketMin, p, ps)
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

      <EventDetailDrawer
        eventId={detailId}
        onClose={() => setDetailId(null)}
        onSelect={setDetailId}
        user={user}
      />
    </div>
  )
}
