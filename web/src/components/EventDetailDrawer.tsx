/**
 * 事件详情抽屉：事件页与告警（聚合）下钻共用。
 *
 * 呈现顺序＝人工判断路径：规则签名 → 监督 → SHAP → 零日 → 请求/响应包 → 反馈 → 同源。
 * body/取证包默认打码；每次读取都由服务端写审计（view_packet / view_sensitive_headers）。
 */
import { useEffect, useRef, useState, type ReactNode } from 'react'
import {
  Alert,
  Button,
  Card,
  Descriptions,
  Drawer,
  Modal,
  Space,
  Table,
  Tag,
  Tooltip,
  Typography,
  message,
} from 'antd'
import ReactEChartsCore from 'echarts-for-react/lib/core'
import echarts from '../echarts'
import { api, download, fmtBytes, fmtInt, fmtNum, fmtTs } from '../api'
import type { EventDetail, EventPacket, PacketMessage, RuleHit, User } from '../types'

const { Text, Paragraph } = Typography

const ACTION_COLOR: Record<string, string> = { block: 'red', alert: 'orange', allow: 'green' }

export function ActionTag({ a }: { a?: string | null }) {
  if (!a) return <Tag>未判定</Tag>
  return <Tag color={ACTION_COLOR[a] || 'default'}>{a}</Tag>
}

function bodyForRaw(m: PacketMessage) {
  if (!m.body_sampled) return `[body 未采样：${m.body_reason || 'off'}]`
  const b = m.body
  if (!b) return `[body 未保留：${m.body_reason || 'unknown'}]`
  if (b.decode_error) return `[原始字节未解码：${b.decode_error}]`
  if (b.decoded_is_binary) return `[二进制内容，${fmtBytes(b.stored_bytes)}；请下载原始字节]`
  return b.decoded_text || '(空)'
}

function messageRaw(m: PacketMessage, side: 'request' | 'response') {
  const line =
    side === 'request'
      ? `${m.method || '-'} ${m.path || '-'}${m.query ? `?${m.query}` : ''} ${m.http_version || ''}`.trim()
      : m.captured
        ? `${m.http_version || ''} ${m.status ?? '-'}`.trim()
        : '[未捕获响应]'
  return [line, ...m.headers.map(([n, v]) => `${n}: ${v}`), '', bodyForRaw(m)].join('\n')
}

function hitTip(hits: RuleHit[]) {
  return (
    <div style={{ whiteSpace: 'pre-line' }}>
      {hits
        .map(
          (h) =>
            `规则：${h.rule}${h.name ? `（${h.name}）` : ''}\n动作：${
              h.action || '未标注'
            }${h.weight !== undefined ? `\n权重：${h.weight}` : ''}`,
        )
        .join('\n\n')}
    </div>
  )
}

function HitSpan({ hits, children }: { hits: RuleHit[]; children: ReactNode }) {
  if (!hits.length) return <>{children}</>
  return (
    <Tooltip title={hitTip(hits)}>
      <span className="packet-hit-inline">{children}</span>
    </Tooltip>
  )
}

type MarkSpan = { start: number; end: number; hits: RuleHit[] }

function mergeMarks(marks: MarkSpan[]) {
  marks.sort((a, b) => a.start - b.start || a.end - b.end)
  const out: MarkSpan[] = []
  for (const m of marks) {
    const last = out[out.length - 1]
    if (!last || m.start >= last.end) {
      out.push({ ...m, hits: [...m.hits] })
      continue
    }
    last.end = Math.max(last.end, m.end)
    for (const h of m.hits) {
      if (!last.hits.includes(h)) last.hits.push(h)
    }
  }
  return out
}

/**
 * 把一条命中收敛到某个字段的红色区间。
 *
 * 新数据由服务端给出 `segments`（规则解码空间 → 当前包文本的精确 UTF-16 区间）。
 * 只有完全没有 segments 的老数据才退回整字段标红；`full` 也只在没有 segments
 * 时才标 method/path/query/body，绝不把请求头或 `?` 一起染红。
 */
function collectMarks(hits: RuleHit[], field: string, length: number) {
  const marks: MarkSpan[] = []
  for (const h of hits) {
    const f = (h.field || '').toLowerCase()
    const segs = (h.segments || []).filter((s) => (s.field || '').toLowerCase() === field)
    if (segs.length) {
      for (const s of segs) {
        const start = Math.max(0, Math.min(length, Number(s.start)))
        const end = Math.max(0, Math.min(length, Number(s.end)))
        if (Number.isFinite(start) && Number.isFinite(end) && end > start) {
          marks.push({ start, end, hits: [h] })
        }
      }
      continue
    }
    const hasSegments = Boolean(h.segments && h.segments.length)
    // 新数据一定带 scope（packet 接口会据此算 segments）。有 scope 却没算出
    // segments 时宁可不标，也不能退回整字段——那正是“正则命中被染成整行”的根因。
    const legacyNoScope = !(h.scope || '').trim()
    if (!hasSegments && legacyNoScope && (f === field || f === 'full') && length > 0) {
      marks.push({ start: 0, end: length, hits: [h] })
    }
  }
  return mergeMarks(marks)
}

function HitText({ text, field, hits }: { text: string; field: string; hits: RuleHit[] }) {
  const marks = collectMarks(hits, field, text.length)
  if (!marks.length) return <>{text}</>
  const out: ReactNode[] = []
  let pos = 0
  marks.forEach((m, i) => {
    if (m.start > pos) out.push(text.slice(pos, m.start))
    out.push(
      <HitSpan hits={m.hits} key={`m-${i}-${m.start}-${m.end}`}>
        {text.slice(m.start, m.end)}
      </HitSpan>,
    )
    pos = m.end
  })
  if (pos < text.length) out.push(text.slice(pos))
  return <>{out}</>
}

function headerField(name: string) {
  const low = name.toLowerCase()
  if (low === 'user-agent') return 'ua'
  if (low === 'referer' || low === 'referrer') return 'referer'
  return ''
}

function PacketSection({
  msg,
  eventID,
  side,
  hits,
  onCopy,
}: {
  msg: PacketMessage
  eventID: number
  side: 'request' | 'response'
  hits: RuleHit[]
  onCopy: (msg: PacketMessage, side: 'request' | 'response') => void
}) {
  const [busy, setBusy] = useState(false)
  const b = msg.body
  const bodyText = bodyForRaw(msg)

  const onDownload = async () => {
    setBusy(true)
    try {
      await download(
        `/api/events/${eventID}/packet/body?side=${side}`,
        `event-${eventID}-${side}.bin`,
      )
    } catch (e: any) {
      message.error(e?.message || '下载失败')
    } finally {
      setBusy(false)
    }
  }

  const knownFields = new Set(['method', 'path', 'query', 'body', 'ua', 'referer'])
  const unknownHits = hits.filter((h) => {
    const f = (h.field || '').toLowerCase()
    return f && f !== 'full' && !knownFields.has(f)
  })
  const allBodyHits = hits.filter((h) => {
    const f = (h.field || '').toLowerCase()
    return f === 'body' || (h.segments || []).some((s) => s.field === 'body')
  })
  const bodyAvailable = Boolean(
    msg.body_sampled && b && !b.decode_error && !b.decoded_is_binary && b.decoded_text,
  )
  // 新数据带 scope；若服务端实在无法映射，前端不猜位置，但要明确告知。
  const unresolvedHits = hits.filter((h) => {
    const f = (h.field || '').toLowerCase()
    const hasScope = Boolean((h.scope || '').trim())
    const hasSegments = Boolean(h.segments && h.segments.length)
    if (hasSegments || !hasScope || !knownFields.has(f)) return false
    return !(f === 'body' && !bodyAvailable) // 正文不可见已有专门标签
  })
  const version = msg.http_version || ''

  const startLine =
    side === 'request' ? (
      <>
        <HitText text={msg.method || '-'} field="method" hits={msg.method ? hits : []} />{' '}
        {msg.path ? <HitText text={msg.path} field="path" hits={hits} /> : '-'}
        {msg.query ? (
          <>
            ?<HitText text={msg.query} field="query" hits={hits} />
          </>
        ) : null}
        {version ? <> {version}</> : null}
      </>
    ) : msg.captured ? (
      `${version} ${msg.status ?? '-'}`.trim()
    ) : (
      '[未捕获响应]'
    )

  const packet = (
    <div className="pre-wrap raw-packet">
      <div className="raw-packet-line">{startLine}</div>
      {msg.headers.map(([name, value], i) => {
        const field = headerField(name)
        return (
          <div className="raw-packet-line" key={`h-${i}`}>
            {field ? (
              <>
                {`${name}: `}
                <HitText text={value} field={field} hits={hits} />
              </>
            ) : (
              `${name}: ${value}`
            )}
          </div>
        )
      })}
      <div className="raw-packet-line">{'\u00a0'}</div>
      <div className="raw-packet-line">
        {bodyAvailable ? (
          <HitText text={bodyText} field="body" hits={hits} />
        ) : (
          bodyText
        )}
      </div>
    </div>
  )

  return (
    <section style={{ marginTop: side === 'response' ? 18 : 0 }}>
      <div className="packet-toolbar">
        <Text strong>{side === 'request' ? '原始请求包' : '原始响应包'}</Text>
        {side === 'response' && msg.sampling_mode ? <Tag>resp-body={msg.sampling_mode}</Tag> : null}
        {side === 'response' && !msg.captured ? <Tag color="orange">未捕获</Tag> : null}
        {msg.body_truncated ? <Tag color="gold">body 已截断</Tag> : null}
        <Button size="small" onClick={() => onCopy(msg, side)}>
          复制{side === 'request' ? '请求' : '响应'}
        </Button>
        <Button size="small" loading={busy} disabled={!b} onClick={onDownload}>
          下载原始体（审计）
        </Button>
      </div>
      <Space size={[6, 4]} wrap style={{ marginBottom: 6 }}>
        <Tag>{msg.headers.length} 个头</Tag>
        <Tag>
          头 {fmtBytes(msg.headers_stored_bytes)} / {fmtBytes(msg.headers_total_bytes)}
        </Tag>
        {msg.headers_truncated ? <Tag color="gold">头已按 8KB 截断</Tag> : null}
        {b ? (
          <>
            <Tag>wire {fmtBytes(b.wire_bytes)}</Tag>
            <Tag>stored {fmtBytes(b.stored_bytes)}</Tag>
            {b.content_encoding.length ? (
              <Tag color="blue">encoding {b.content_encoding.join(' → ')}</Tag>
            ) : null}
            {b.truncated ? <Tag color="gold">原始体已截断</Tag> : null}
            {b.decode_truncated ? <Tag color="gold">解码输出 &gt;1MB 已截断</Tag> : null}
            {b.legacy_lossy ? <Tag color="orange">legacy lossy</Tag> : null}
          </>
        ) : (
          <Tag color="gold">未采样：{msg.body_reason || 'unknown'}</Tag>
        )}
        {allBodyHits.length && !bodyAvailable ? (
          <Tag color="red">body 命中但正文不可见，未标位</Tag>
        ) : null}
        {unknownHits.length ? (
          <Tooltip title={hitTip(unknownHits)}>
            <Tag color="orange">命中字段未映射</Tag>
          </Tooltip>
        ) : null}
        {unresolvedHits.length ? (
          <Tooltip title={hitTip(unresolvedHits)}>
            <Tag color="orange">命中无法精确标位</Tag>
          </Tooltip>
        ) : null}
      </Space>
      {packet}
    </section>
  )
}

export default function EventDetailDrawer({
  eventId,
  onClose,
  onSelect,
  user,
}: {
  /** 要展示的事件 id；null 时关闭。 */
  eventId: number | null
  onClose: () => void
  /** 请求切换展示另一个事件（同源关联行点击）。 */
  onSelect?: (id: number) => void
  user: User
}) {
  const canWrite = user.role !== 'viewer'
  const canBody = user.role === 'analyst' || user.role === 'admin'

  const [detail, setDetail] = useState<EventDetail | null>(null)
  const [packet, setPacket] = useState<EventPacket | null>(null)
  const [packetErr, setPacketErr] = useState('')
  const [packetLoading, setPacketLoading] = useState(false)
  const [reveal, setReveal] = useState(false)
  const packetSeq = useRef(0)
  const detailSeq = useRef(0)

  const loadPacket = async (id: number, revealFlag: boolean) => {
    const seq = ++packetSeq.current
    setPacketLoading(true)
    setPacketErr('')
    try {
      const r = await api<EventPacket>(
        `/api/events/${id}/packet?reveal=${revealFlag ? 1 : 0}`,
      )
      if (seq !== packetSeq.current) return false
      setPacket(r)
      return true
    } catch (e: any) {
      if (seq === packetSeq.current) setPacketErr(e?.message || '取证包读取失败')
      return false
    } finally {
      if (seq === packetSeq.current) setPacketLoading(false)
    }
  }

  const openDetail = async (id: number) => {
    packetSeq.current += 1
    const seq = ++detailSeq.current
    setPacket(null)
    setPacketErr('')
    setReveal(false)
    try {
      const d = await api<EventDetail>(`/api/events/${id}`)
      if (seq !== detailSeq.current) return
      setDetail(d)
      if (canBody) await loadPacket(id, false)
    } catch (e: any) {
      if (seq === detailSeq.current) message.error(e?.message || '详情加载失败')
    }
  }

  useEffect(() => {
    if (eventId == null) {
      packetSeq.current += 1
      detailSeq.current += 1
      setDetail(null)
      setPacket(null)
      setPacketErr('')
      setReveal(false)
      return
    }
    openDetail(eventId)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [eventId])

  const closeDetail = () => {
    onClose()
  }

  const selectEvent = (id: number) => {
    if (onSelect) onSelect(id)
    else openDetail(id)
  }

  const revealSensitive = () => {
    if (!detail || !packet) return
    const names = packet.sensitive_headers.length
      ? packet.sensitive_headers.join('、')
      : '（当前包没有命中默认敏感头）'
    Modal.confirm({
      title: '显示敏感头原值？',
      content:
        `本次会请求完整头值并写入审计（view_sensitive_headers）。` +
        `默认打码头：${names}。切换 Tab 或关闭抽屉后立即丢弃。`,
      okText: '显示并审计',
      cancelText: '取消',
      onOk: async () => {
        const ok = await loadPacket(detail.id, true)
        if (ok) setReveal(true)
      },
    })
  }

  const copyText = async (text: string, label: string) => {
    try {
      await navigator.clipboard.writeText(text)
      message.success(`${label}已复制`)
    } catch (e: any) {
      message.error(e?.message || '复制失败')
    }
  }

  const sendFeedback = async (verdict: string) => {
    if (!detail) return
    try {
      await api('/api/feedback', {
        method: 'POST',
        body: { event_id: detail.id, verdict, note: null },
      })
      message.success('反馈已记录（独立台账，不会覆盖模型输出）')
      openDetail(detail.id)
    } catch (e: any) {
      message.error(e?.message || '提交失败')
    }
  }

  const shap = detail?.shap || []
  const ruleHits = detail?.rule_hits || []
  // 取证包接口会返回与展示文本对齐的 segments；优先用它做精确标位。
  const packetHits = packet?.rule_hits?.length ? packet.rule_hits : ruleHits
  const supHit = (detail?.supervised_score ?? 0) >= (detail?.supervised_threshold ?? 1)
  const shapOption = {
    grid: { left: 150, right: 60, top: 16, bottom: 28 },
    tooltip: {
      trigger: 'axis',
      formatter: (ps: any) => {
        const p = ps[0]
        const item = [...shap].reverse()[p.dataIndex]
        if (!item) return ''
        return `${item.feature}<br/>值=${fmtNum(item.value, 6)}<br/>贡献=${fmtNum(item.contribution, 6)}`
      },
    },
    xAxis: { type: 'value', name: '贡献' },
    yAxis: {
      type: 'category',
      data: [...shap].reverse().map((s) => s.feature),
      axisLabel: { fontSize: 11 },
    },
    series: [
      {
        type: 'bar',
        data: [...shap]
          .reverse()
          .map((s) => ({
            value: s.contribution,
            itemStyle: { color: s.contribution >= 0 ? '#cf1322' : '#389e0d' },
          })),
      },
    ],
  }

  return (
    <Drawer
      width={980}
      open={eventId != null}
      onClose={closeDetail}
      title={detail ? `事件 #${detail.id}` : eventId != null ? `事件 #${eventId}` : ''}
    >
      {detail ? (
        <div>
          <Space style={{ marginBottom: 12 }}>
            <ActionTag a={detail.action} />
            {detail.dry_run ? <Tag color="orange">dry-run（只记录）</Tag> : null}
            {detail.rule_testing ? (
              <Tooltip title="本条命中里包含「未合格、测试中」的规则；命中的告警是真实产生的，但该规则还不能 block">
                <Tag color="blue">测试命中</Tag>
              </Tooltip>
            ) : null}
            {detail.attack_type ? <Tag color="volcano">{detail.attack_type}</Tag> : null}
            {detail.body_truncated ? <Tag color="gold">body 已截断</Tag> : null}
          </Space>

          {/* 呈现顺序＝人工判断路径：规则签名 → 监督 → SHAP → 零日 → 请求/响应包 → 反馈 → 同源 */}
          <Card
            size="small"
            title="① 规则签名（在解码后文本上匹配）"
            extra={
              detail.rule_set_sha1_16 ? (
                <span className="muted mono">规则集 {detail.rule_set_sha1_16}</span>
              ) : null
            }
          >
            {ruleHits.length ? (
              <Table
                size="small"
                rowKey={(r: any) => `${r.rule}|${r.field || ''}`}
                pagination={false}
                dataSource={ruleHits}
                columns={[
                  {
                    title: '规则',
                    dataIndex: 'rule',
                    width: 180,
                    render: (v) => <Text code>{v}</Text>,
                  },
                  { title: '名称', dataIndex: 'name', width: 150, render: (v) => v || '-' },
                  {
                    title: '动作',
                    dataIndex: 'action',
                    width: 84,
                    render: (v) => (
                      <Tag color={v === 'block' ? 'red' : 'gold'}>
                        {v === 'block' ? '阻断' : '告警'}
                      </Tag>
                    ),
                  },
                  { title: '权重', dataIndex: 'weight', width: 68, align: 'right' },
                  { title: '字段', dataIndex: 'field', width: 76 },
                  {
                    title: '命中片段',
                    dataIndex: 'snippet',
                    ellipsis: true,
                    render: (v) => (v ? <Text code>{v}</Text> : '-'),
                  },
                ]}
              />
            ) : (
              <div className="muted">
                本条无规则命中。规则层在解码后文本上匹配，只作证据：既不参与训练标签，也不覆盖模型输出。
              </div>
            )}
          </Card>

          <Card size="small" title="② 监督通道（当前唯一的阻断依据）" style={{ marginTop: 12 }}>
            <Descriptions size="small" bordered column={2}>
              <Descriptions.Item label="分数 (1 − P(normal))">
                <Text strong={supHit} type={supHit ? 'danger' : undefined}>
                  {fmtNum(detail.supervised_score, 6)}
                </Text>
              </Descriptions.Item>
              <Descriptions.Item label="阈值（标定池留出）">
                {fmtNum(detail.supervised_threshold, 6)}
              </Descriptions.Item>
              <Descriptions.Item label="是否命中">
                {supHit ? <Tag color="red">命中 → block</Tag> : <Tag>未命中</Tag>}
              </Descriptions.Item>
              <Descriptions.Item label="攻击类型（argmax，仅归类）">
                {detail.attack_type ? <Tag color="volcano">{detail.attack_type}</Tag> : '-'}
              </Descriptions.Item>
            </Descriptions>
          </Card>

          <Card
            size="small"
            title="③ 模型归因（TreeSHAP Top-8，针对预测类）"
            style={{ marginTop: 12 }}
            extra={<span className="muted">红色推高、绿色拉低；仅供解释，不参与判定</span>}
          >
            {shap.length ? (
              <ReactEChartsCore echarts={echarts} option={shapOption} style={{ height: 300 }} />
            ) : (
              <div className="muted">该记录没有归因数据（树件/特征名缺失时为正常现象）</div>
            )}
          </Card>

          <Card
            size="small"
            title="④ 零日通道（默认关闭；仅告警、从不单独阻断）"
            style={{ marginTop: 12 }}
          >
            <Descriptions size="small" bordered column={2}>
              <Descriptions.Item label="分数 (−avg_path_len)">
                {fmtNum(detail.zero_day_score, 6)}
              </Descriptions.Item>
              <Descriptions.Item label="阈值">{fmtNum(detail.zero_day_threshold, 6)}</Descriptions.Item>
              <Descriptions.Item label="通道开关">
                <Tag color={detail.zero_day_enabled ? 'red' : 'default'}>
                  {detail.zero_day_enabled ? '开启（参与融合）' : '关闭（安全降级）'}
                </Tag>
              </Descriptions.Item>
              <Descriptions.Item label="原始穿阈（留证）">
                {detail.zero_day_score_crossed ? '是' : '否'}
              </Descriptions.Item>
              <Descriptions.Item label="生效命中（受开关约束）">
                {detail.zero_day_flagged ? '是' : '否'}
              </Descriptions.Item>
              <Descriptions.Item label="分数语义">
                <span className="muted">「没见过」不等于「确认是攻击」</span>
              </Descriptions.Item>
            </Descriptions>
          </Card>

          {canBody ? (
            <Card
              size="small"
              title="⑤ 原始请求包 / 原始响应包"
              style={{ marginTop: 12 }}
              extra={
                <Space wrap>
                  {packet && reveal ? <Tag color="orange">敏感值已显示</Tag> : null}
                  {packet && packet.sensitive_headers.length && !reveal ? (
                    <Button size="small" onClick={revealSensitive}>
                      显示敏感值（审计）
                    </Button>
                  ) : null}
                </Space>
              }
            >
              {packetErr ? (
                <Alert
                  type="error"
                  showIcon
                  message={packetErr}
                  action={
                    <Button size="small" onClick={() => detail && loadPacket(detail.id, reveal)}>
                      重试
                    </Button>
                  }
                />
              ) : null}
              {packetLoading && !packet ? <div className="muted">取证包读取中…</div> : null}
              {!packetLoading && !packet && !packetErr ? (
                <div className="muted">
                  未加载取证包。需要 analyst 及以上角色；旧事件或 raw 已清理时只能重建。
                </div>
              ) : null}
              {packet ? (
                <>
                  {packet.reconstructed ? (
                    <Alert
                      type="warning"
                      showIcon
                      style={{ marginBottom: 10 }}
                      message="这不是完整 wire 包：raw 缺失或来自旧采集器，字段已重建。"
                      description={`原因：${packet.reconstructed_reason || 'unknown'}。重建不会伪造不存在的头或 body。`}
                    />
                  ) : null}
                  <div className="muted" style={{ fontSize: 12, marginBottom: 10 }}>
                    {ruleHits.length
                      ? `规则命中 ${ruleHits.length} 条；红色＝正则实际命中的片段。`
                      : '本条无规则命中，因此没有红色标记。'}
                    {reveal ? '敏感头原值已显示（本次已审计）。' : '敏感头值逐字符显示 *。'}
                    响应包仅人工复核。
                  </div>
                  <PacketSection
                    msg={packet.request}
                    eventID={packet.event_id}
                    side="request"
                    hits={packetHits}
                    onCopy={(m, s) =>
                      copyText(messageRaw(m, s), s === 'request' ? '请求' : '响应')
                    }
                  />
                  <PacketSection
                    msg={packet.response}
                    eventID={packet.event_id}
                    side="response"
                    hits={[]}
                    onCopy={(m, s) =>
                      copyText(messageRaw(m, s), s === 'request' ? '请求' : '响应')
                    }
                  />
                </>
              ) : null}
            </Card>
          ) : (
            <Card size="small" title="⑤ 请求字段" style={{ marginTop: 12 }}>
              <Alert
                type="info"
                showIcon
                style={{ marginBottom: 8 }}
                message="viewer 不读取取证包；以下为事件表里已有的字段与响应状态摘要。"
              />
              <Descriptions size="small" bordered column={2}>
                <Descriptions.Item label="时间">{fmtTs(detail.ts)}</Descriptions.Item>
                <Descriptions.Item label="来源">
                  {detail.src_ip}:{detail.src_port}
                </Descriptions.Item>
                <Descriptions.Item label="Host">{detail.host}</Descriptions.Item>
                <Descriptions.Item label="响应状态">{detail.status ?? '-'}</Descriptions.Item>
                <Descriptions.Item label="方法">{detail.method}</Descriptions.Item>
                <Descriptions.Item label="耗时">{fmtNum(detail.dur_ms, 3)} ms</Descriptions.Item>
                <Descriptions.Item label="路径" span={2}>
                  <Text code>{detail.path}</Text>
                </Descriptions.Item>
                <Descriptions.Item label="查询串" span={2}>
                  <Text code>{detail.query || '(空)'}</Text>
                </Descriptions.Item>
                <Descriptions.Item label="UA" span={2}>
                  <Text code>{detail.ua || '(空)'}</Text>
                </Descriptions.Item>
                <Descriptions.Item label="请求 body 长度">
                  {fmtInt(detail.body_len)} {detail.body_truncated ? '(截断)' : ''}
                </Descriptions.Item>
                <Descriptions.Item label="上下行字节">
                  {fmtInt(detail.bytes_in)} / {fmtInt(detail.bytes_out)}
                </Descriptions.Item>
                <Descriptions.Item label="策略版本">v{detail.policy_version ?? '-'}</Descriptions.Item>
                <Descriptions.Item label="产物目录">
                  <span className="mono">{detail.model_artifacts}</span>
                </Descriptions.Item>
              </Descriptions>
            </Card>
          )}

          <Card size="small" title="人工反馈" style={{ marginTop: 12 }}
            extra={<span className="muted">写入独立台账，不会覆盖 pred</span>}>
            {canWrite ? (
              <Space wrap>
                <Tooltip title="模型/规则报了，但这条请求是攻击（确认攻击）">
                  <Button danger onClick={() => sendFeedback('confirmed_attack')}>确认攻击</Button>
                </Tooltip>
                <Tooltip title="模型/规则报了，但这条请求是正常业务（误报）">
                  <Button onClick={() => sendFeedback('false_positive')}>误报</Button>
                </Tooltip>
                <Tooltip title="模型没报，但人工确认是正常业务（用于规则/模型的良性证据）">
                  <Button onClick={() => sendFeedback('confirmed_benign')}>正常业务</Button>
                </Tooltip>
                <Button onClick={() => sendFeedback('missed')}>漏报</Button>
                <Button onClick={() => sendFeedback('uncertain')}>待查</Button>
              </Space>
            ) : (
              <div className="muted">当前角色（viewer）无反馈权限</div>
            )}
            {detail.feedback?.length ? (
              <Table
                size="small"
                style={{ marginTop: 12 }}
                rowKey="id"
                pagination={false}
                dataSource={detail.feedback}
                columns={[
                  { title: '时间', dataIndex: 'ts', render: (v) => fmtTs(v) },
                  { title: '结论', dataIndex: 'verdict' },
                  { title: '操作人', dataIndex: 'actor' },
                  { title: '备注', dataIndex: 'note' },
                ]}
              />
            ) : null}
          </Card>

          <Card size="small" title="⑥ 同源关联（同 IP，±10 分钟）" style={{ marginTop: 12 }}>
            <Table
              size="small"
              rowKey="id"
              pagination={false}
              dataSource={detail.related || []}
              onRow={(r: any) => ({ onClick: () => selectEvent(r.id), style: { cursor: 'pointer' } })}
              columns={[
                { title: '时间', dataIndex: 'ts', width: 165, render: (v) => fmtTs(v) },
                { title: '动作', dataIndex: 'action', width: 84, render: (v) => <ActionTag a={v} /> },
                { title: '路径', dataIndex: 'path', ellipsis: true },
                {
                  title: '监督分',
                  dataIndex: 'supervised_score',
                  width: 100,
                  render: (v) => fmtNum(v, 4),
                },
              ]}
            />
          </Card>

          <Paragraph className="muted" style={{ marginTop: 12 }}>
            判定规则：监督分数 ≥ 阈值，或「已合格且 action=block」的规则权重和 ≥ 阻断线 → block；
            零日穿阈（通道开启）或规则通道有命中但不够阻断线 → alert；其余 allow。
            零日关闭时分数与原始穿阈仍记录，但不产生 alert。
            <b>未合格、测试中的规则一律强制 alert</b>：它们的命中会真的产生告警（<Text code>rule_testing</Text>），
            但绝不阻断。规则命中是证据，不是训练标签。
          </Paragraph>
        </div>
      ) : (
        <div className="muted">加载中…</div>
      )}
    </Drawer>
  )
}
