import { useCallback, useEffect, useState } from 'react'
import {
  Alert,
  Card,
  Col,
  Descriptions,
  Row,
  Select,
  Space,
  Statistic,
  Switch,
  Table,
  Tag,
  Tooltip,
  Typography,
  Button,
} from 'antd'
import { ReloadOutlined } from '@ant-design/icons'
import ReactEChartsCore from 'echarts-for-react/lib/core'
import echarts from '../echarts'
import { api, fmtInt, fmtNum, fmtPct, fmtTs } from '../api'
import type { ReloadView } from '../types'

const { Title, Text } = Typography

const HIST_LABELS = ['0-.1', '.1-.2', '.2-.3', '.3-.4', '.4-.5', '.5-.6', '.6-.7', '.7-.8', '.8-.9', '.9-1']

/** 站点状态：把「这个站点的流量是谁在判、和现役对不对得上」压成一眼可读。 */
const SITE_STATUS: Record<string, { color: string; text: string; hint: string }> = {
  in_sync: {
    color: 'green',
    text: '与现役一致',
    hint: '最新判决用的就是现役策略修订（模型 + 阈值 + 规则全一致）',
  },
  policy_old: {
    color: 'gold',
    text: '策略修订落后',
    hint: '模型与现役是同一套，只是阈值/规则还是旧修订；采集器热重载后即可对齐',
  },
  stale: {
    color: 'red',
    text: '模型落后',
    hint: '最新判决的监督模型 sha1 与现役不同：采集器仍在用旧产物，需重新切换/重启',
  },
  unscored: {
    color: 'default',
    text: '窗口内无判决',
    hint: '该站点窗口内的事件没有判定信息（采集器未 --score，或没上报 policy_version）',
  },
  unknown: {
    color: 'orange',
    text: '无法对比',
    hint: '策略快照缺失或现役策略读不到；只能展示留证里的产物目录',
  },
}

/** 一个模型单元格：优先显示注册表里的可读名，其次文件名，右侧挂 sha1 前 16 位。 */
function ModelCell({ m }: { m?: any }) {
  if (!m?.artifact && !m?.sha1_16) return <span className="muted">-</span>
  return (
    <Space size={4} wrap>
      <span>{m.name || m.artifact || '未登记模型'}</span>
      {m.sha1_16 ? (
        <Text code className="muted" style={{ fontSize: 11 }}>
          {m.sha1_16}
        </Text>
      ) : null}
    </Space>
  )
}

/** 热重载状态：一句话说清「控制台看到的」和「数据面在跑的」是不是同一版。 */
function ReloadTag({ rv }: { rv?: ReloadView }) {
  if (!rv) return <span className="muted">-</span>
  if (!rv.available) {
    return (
      <Tooltip title={rv.reason}>
        <Tag color="orange">未上报（确认采集器在跑且未用 --no-reload）</Tag>
      </Tooltip>
    )
  }
  const bad = rv.rules_effective_drift
  const pending = !bad && (rv.policy_drift || rv.rules_drift)
  return (
    <Space size={4} wrap>
      <Tag color={bad ? 'red' : pending ? 'gold' : 'green'}>
        {bad
          ? '规则改动未生效（轮询过但没换成）'
          : pending
            ? '磁盘更新待轮询'
            : `已对齐（每 ${rv.interval_sec ?? '?'}s 轮询）`}
      </Tag>
      <span className="muted">
        策略修订 {rv.policy_active_revision ?? '-'}/{rv.policy_revision ?? '-'} · 规则{' '}
        {rv.rules_active_n != null ? `${rv.rules_active_n} 条` : '-'}
      </span>
      {rv.last_err ? (
        <Tooltip title={rv.last_err}>
          <Tag color="red">最近一次重载失败</Tag>
        </Tooltip>
      ) : null}
    </Space>
  )
}

export default function Overview() {
  const [hours, setHours] = useState(24)
  const [auto, setAuto] = useState(false)
  const [d, setD] = useState<any>(null)
  const [err, setErr] = useState('')

  const load = useCallback(async () => {
    try {
      setErr('')
      setD(await api<any>(`/api/overview/summary?window_hours=${hours}`))
    } catch (e: any) {
      setErr(e?.message || '加载失败')
    }
  }, [hours])

  useEffect(() => {
    load()
  }, [load])

  useEffect(() => {
    if (!auto) return
    const t = setInterval(load, 15000)
    return () => clearInterval(t)
  }, [auto, load])

  const t = d?.totals || {}
  const pol = d?.policy || {}
  const col = d?.collector || null
  const sites = d?.sites || null
  const siteItems = sites?.items || []
  const liveSite = sites?.live || null

  const histOption = {
    tooltip: { trigger: 'axis' },
    grid: { left: 48, right: 16, top: 16, bottom: 36 },
    xAxis: { type: 'category', data: HIST_LABELS, axisLabel: { fontSize: 11 } },
    yAxis: { type: 'value' },
    series: [
      {
        type: 'bar',
        data: d?.score_histogram || [],
        itemStyle: { color: '#1677ff' },
        name: '请求数',
      },
    ],
  }

  const pieData = (d?.top_attack_types || []).map((x: any) => ({
    name: x.attack_type || 'unknown',
    value: x.n,
  }))
  const pieOption = {
    tooltip: { trigger: 'item' },
    legend: { bottom: 0, type: 'scroll' },
    series: [
      {
        type: 'pie',
        radius: ['38%', '66%'],
        center: ['50%', '44%'],
        data: pieData,
        label: { fontSize: 11 },
      },
    ],
  }

  return (
    <div>
      <div className="toolbar">
        <Title level={4} className="page-title">
          总览
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
            { value: 24 * 30, label: '近 30 天' },
          ]}
        />
        <span className="muted">自动刷新 15s</span>
        <Switch size="small" checked={auto} onChange={setAuto} />
        <Button icon={<ReloadOutlined />} onClick={load} size="small">
          刷新
        </Button>
        {d?.mode ? (
          <Tag color={d.mode === 'enforce' ? 'red' : d.mode === 'dry_run' ? 'orange' : d.mode === 'off' || d.mode === 'collect_only' ? 'blue' : 'default'}>
            {d.mode === 'enforce' ? '拦截中（enforce）' : d.mode === 'dry_run' ? 'dry-run（只记录不阻断）' : d.mode === 'off' || d.mode === 'collect_only' ? '纯采集' : '采集器状态未知'}
          </Tag>
        ) : null}
      </div>

      {err ? <Alert type="error" message={err} showIcon style={{ marginBottom: 12 }} /> : null}
      {(d?.warnings || []).map((w: string, i: number) => (
        <Alert key={i} type="warning" message={w} showIcon style={{ marginBottom: 8 }} />
      ))}

      <Row gutter={[12, 12]}>
        <Col xs={12} md={6} lg={3}>
          <Card size="small">
            <Statistic title="请求数" value={t.n || 0} />
          </Card>
        </Col>
        <Col xs={12} md={6} lg={3}>
          <Card size="small">
            <Statistic
              title={d?.mode === 'enforce' ? '实际拦截（403）' : 'dry-run 判定阻断'}
              value={(d?.mode === 'enforce' ? t.enforced : t.blocks) || 0}
              valueStyle={{ color: '#cf1322' }}
            />
          </Card>
        </Col>
        <Col xs={12} md={6} lg={3}>
          <Card size="small">
            <Statistic title="零日告警" value={t.alerts || 0} valueStyle={{ color: '#d46b08' }} />
          </Card>
        </Col>
        <Col xs={12} md={6} lg={3}>
          <Card size="small">
            <Statistic title="放行" value={t.allows || 0} valueStyle={{ color: '#389e0d' }} />
          </Card>
        </Col>
        <Col xs={12} md={6} lg={3}>
          <Card size="small">
            <Tooltip title="监督通道分数 ≥ 阈值（判定依据）">
              <Statistic title="监督命中" value={t.sup_flagged || 0} />
            </Tooltip>
          </Card>
        </Col>
        <Col xs={12} md={6} lg={3}>
          <Card size="small">
            <Tooltip title="零日通道原始穿阈数（与通道开关无关，留证用）">
              <Statistic title="零日原始穿阈" value={t.zd_crossed || 0} />
            </Tooltip>
          </Card>
        </Col>
        <Col xs={12} md={6} lg={3}>
          <Card size="small">
            <Statistic title="平均耗时" value={fmtNum(t.avg_dur_ms, 3)} suffix="ms" />
          </Card>
        </Col>
        <Col xs={12} md={6} lg={3}>
          <Card size="small">
            <Tooltip title="最近一条事件时间；采集→入库的滞后">
              <Statistic title="入库滞后" value={d?.ingest?.lag_sec ?? '-'} suffix="s" />
            </Tooltip>
          </Card>
        </Col>
      </Row>

      <Row gutter={[12, 12]} style={{ marginTop: 12 }}>
        <Col span={24}>
          <Card
            size="small"
            title="站点 → 模型（一个 WAF 接多站点时，每个站点实际在跑哪套模型）"
            extra={
              liveSite ? (
                <Space size={6} wrap>
                  <span className="muted">现役</span>
                  <Tag color="blue">v{liveSite.policy_version ?? '-'}</Tag>
                  <Tag>监督 {liveSite.supervised?.name || liveSite.supervised?.artifact || '-'}</Tag>
                  <Tag color={liveSite.zero_day?.enabled ? 'red' : 'default'}>
                    零日 {liveSite.zero_day?.enabled ? '开启' : '关闭'}
                  </Tag>
                  <Tag>
                    规则{' '}
                    {liveSite.rules?.enabled
                      ? `${fmtInt(liveSite.rules?.n_rules)} 条`
                      : '未启用'}
                  </Tag>
                </Space>
              ) : null
            }
          >
            <Table
              size="small"
              rowKey={(r: any) => String(r.host ?? '(no-host)')}
              dataSource={siteItems}
              pagination={siteItems.length > 10 ? { pageSize: 10, size: 'small' } : false}
              scroll={{ x: 980 }}
              locale={{
                emptyText: (
                  <span className="muted">
                    窗口内没有事件；采集器接上并入库后这里会按 Host 列出每个站点用的模型
                  </span>
                ),
              }}
              expandable={{
                rowExpandable: (r: any) => (r.versions || []).length > 1,
                expandedRowRender: (r: any) => (
                  <Table
                    size="small"
                    rowKey={(x: any) => String(x.policy_version)}
                    pagination={false}
                    dataSource={r.versions || []}
                    columns={[
                      {
                        title: '策略修订',
                        dataIndex: 'policy_version',
                        width: 110,
                        render: (v: number) => <Tag>v{v}</Tag>,
                      },
                      { title: '请求', dataIndex: 'n', width: 90, align: 'right' },
                      {
                        title: '最后使用',
                        dataIndex: 'last_ts',
                        width: 180,
                        render: (v: number) => fmtTs(v),
                      },
                      {
                        title: '监督模型',
                        width: 260,
                        render: (_: any, x: any) =>
                          x.snapshot_found ? (
                            <ModelCell m={x.supervised} />
                          ) : (
                            <Tag color="orange">策略快照缺失</Tag>
                          ),
                      },
                    ]}
                  />
                ),
              }}
              columns={[
                {
                  title: '站点（Host）',
                  dataIndex: 'host',
                  width: 220,
                  render: (h: string, r: any) => (
                    <div>
                      <div>
                        {h ? <Text strong>{h}</Text> : <Tag color="default">未上报 Host</Tag>}
                      </div>
                      <div className="muted" style={{ fontSize: 11 }}>
                        {r.latest?.rules?.enabled ? (
                          <Tooltip title={`规则集 sha1 ${r.latest.rules.sha1_16 || '-'}`}>
                            <span>
                              规则 {fmtInt(r.latest.rules.n_rules)} 条 · block{' '}
                              {fmtInt(r.latest.rules.n_block_rules)}
                            </span>
                          </Tooltip>
                        ) : (
                          <span>规则未启用</span>
                        )}
                        {(r.artifact_dirs || []).length ? (
                          <Tooltip title={(r.artifact_dirs || []).join('\n')}>
                            <span> · 产物 {r.artifact_dirs.length} 个</span>
                          </Tooltip>
                        ) : null}
                      </div>
                    </div>
                  ),
                },
                {
                  title: '请求',
                  dataIndex: 'n',
                  width: 80,
                  align: 'right',
                  render: (v: number) => fmtInt(v),
                },
                {
                  title: '状态',
                  width: 140,
                  render: (_: any, r: any) => {
                    const s = SITE_STATUS[r.status] || SITE_STATUS.unknown
                    return (
                      <Tooltip
                        title={
                          r.status === 'unknown' && (r.stale_versions || 0) > 0
                            ? `${s.hint}（另有 ${r.stale_versions} 个旧版本用过不同模型）`
                            : s.hint
                        }
                      >
                        <Tag color={s.color}>{s.text}</Tag>
                      </Tooltip>
                    )
                  },
                },
                {
                  title: '最新判决',
                  width: 140,
                  render: (_: any, r: any) =>
                    r.latest ? (
                      <div>
                        <Tag color="blue">v{r.latest.policy_version}</Tag>
                        <div className="muted" style={{ fontSize: 11 }}>
                          {fmtTs(r.latest.last_ts)}
                        </div>
                      </div>
                    ) : (
                      <span className="muted">-</span>
                    ),
                },
                {
                  title: '监督模型（判定用）',
                  width: 240,
                  render: (_: any, r: any) => <ModelCell m={r.latest?.supervised} />,
                },
                {
                  title: '零日模型',
                  width: 180,
                  render: (_: any, r: any) =>
                    r.latest ? (
                      <Space size={4} wrap>
                        <ModelCell m={r.latest.zero_day} />
                        {r.latest.zero_day?.enabled ? (
                          <Tag color="red">开启</Tag>
                        ) : (
                          <Tag>关闭</Tag>
                        )}
                      </Space>
                    ) : (
                      <span className="muted">-</span>
                    ),
                },
              ]}
            />
            <div className="muted" style={{ marginTop: 8 }}>
              口径：按窗口内每条判决的 <Text code>host</Text> +{' '}
              <Text code>policy_version</Text> 归组，再用{' '}
              <Text code>policy_versions</Text> 快照里的产物 sha1 还原「这条判决是谁算的」，
              产物目录取 <Text code>events.model_artifacts</Text>。多站点共用一个采集器时模型相同；
              某站点 <Tag color="red">模型落后</Tag> 通常是切模型后该站点链路没重启。
            </div>
          </Card>
        </Col>
      </Row>

      <Row gutter={[12, 12]} style={{ marginTop: 12 }}>
        <Col xs={24} lg={12}>
          <Card size="small" title="监督通道分数分布（1 − P(normal)）">
            <ReactEChartsCore echarts={echarts} option={histOption} style={{ height: 260 }} />
          </Card>
        </Col>
        <Col xs={24} lg={12}>
          <Card size="small" title="命中攻击类型（argmax，仅归类）">
            {pieData.length ? (
              <ReactEChartsCore echarts={echarts} option={pieOption} style={{ height: 260 }} />
            ) : (
              <div className="muted" style={{ padding: 40, textAlign: 'center' }}>
                窗口内无监督命中
              </div>
            )}
          </Card>
        </Col>
      </Row>

      <Row gutter={[12, 12]} style={{ marginTop: 12 }}>
        <Col xs={24} lg={12}>
          <Card size="small" title="策略（唯一事实来源：artifacts/decision_policy.json）">
            <Descriptions size="small" column={1} bordered>
              <Descriptions.Item label="版本">v{pol.version ?? '-'}</Descriptions.Item>
              <Descriptions.Item label="生成时间">{pol.generated_at || '-'}</Descriptions.Item>
              <Descriptions.Item label="监督阈值">
                <Text code>{fmtNum(pol.supervised_threshold, 6)}</Text>
              </Descriptions.Item>
              <Descriptions.Item label="零日阈值">
                <Text code>{fmtNum(pol.zero_day_threshold, 6)}</Text>{' '}
                <Tag color={pol.zero_day_enabled ? 'red' : 'default'}>
                  {pol.zero_day_enabled ? '通道开启' : '通道关闭（安全降级）'}
                </Tag>
              </Descriptions.Item>
              <Descriptions.Item label="标定池">
                {pol.calibration_pool || '-'}（n={fmtInt(pol.calibration_n)}）
              </Descriptions.Item>
              <Descriptions.Item label="生效融合池上 FPR">
                {fmtPct(pol.effective_fused_fpr_on_pool, 3)}
              </Descriptions.Item>
            </Descriptions>
          </Card>
        </Col>
        <Col xs={24} lg={12}>
          <Card size="small" title="采集面（waf-collector 指标文件）">
            {col ? (
              <Descriptions size="small" column={2} bordered>
                <Descriptions.Item label="监听">{col.listen}</Descriptions.Item>
                <Descriptions.Item label="上游">{col.upstream}</Descriptions.Item>
                <Descriptions.Item label="已写记录">{fmtInt(col.written)}</Descriptions.Item>
                <Descriptions.Item label="字节">{fmtInt(col.bytes)}</Descriptions.Item>
                <Descriptions.Item label="丢（队列满）">
                  <Text type={col.dropped_queue_full ? 'danger' : undefined}>
                    {fmtInt(col.dropped_queue_full)}
                  </Text>
                </Descriptions.Item>
                <Descriptions.Item label="丢（写盘失败）">
                  <Text type={col.dropped_io ? 'danger' : undefined}>{fmtInt(col.dropped_io)}</Text>
                </Descriptions.Item>
                <Descriptions.Item label="判定 dry-run">
                  <Tag>{col.score_enabled ? '已接线（只记录）' : '未接线'}</Tag>
                </Descriptions.Item>
                <Descriptions.Item label="判定失败">{fmtInt(col.score_errors)}</Descriptions.Item>
                <Descriptions.Item label="动作 allow/block/alert" span={2}>
                  {fmtInt(col.actions_allow)} / {fmtInt(col.actions_block)} / {fmtInt(col.actions_alert)}
                </Descriptions.Item>
                <Descriptions.Item label="规则通道" span={2}>
                  {pol?.rules_enabled ? (
                    <span>
                      <Tag color="green">
                        {fmtInt(pol.rules_n)} 条 / block {fmtInt(pol.rules_n_block)}
                      </Tag>
                      <Text code>{pol.rules_sha1_16}</Text>
                    </span>
                  ) : (
                    <Tag color="orange">未启用（全局刹车）</Tag>
                  )}
                </Descriptions.Item>
                <Descriptions.Item label="热重载" span={2}>
                  <ReloadTag rv={col.reload_view} />
                </Descriptions.Item>
                <Descriptions.Item label="指标时间" span={2}>
                  {fmtTs(col.ts)}{' '}
                  <Tag color={col.stale ? 'red' : 'green'}>
                    {col.stale ? `已 ${col.age_sec}s 未刷新` : '新鲜'}
                  </Tag>
                </Descriptions.Item>
              </Descriptions>
            ) : (
              <Alert
                type="info"
                showIcon
                message="未读到采集器指标"
                description={
                  <span className="mono">
                    启动采集器时加 --stats-out F:\waf\traindata\proxy\collector-metrics.json
                  </span>
                }
              />
            )}
          </Card>
        </Col>
      </Row>

      <Row gutter={[12, 12]} style={{ marginTop: 12 }}>
        <Col xs={24} lg={12}>
          <Card size="small" title="Top 路径（block/alert）">
            <Table
              size="small"
              rowKey={(r: any) => r.path + r.n}
              pagination={false}
              dataSource={d?.top_paths || []}
              columns={[
                { title: '路径', dataIndex: 'path', ellipsis: true },
                { title: '次数', dataIndex: 'n', width: 90, align: 'right' },
              ]}
            />
          </Card>
        </Col>
        <Col xs={24} lg={12}>
          <Card size="small" title="入库状态">
            <Descriptions size="small" column={1} bordered>
              <Descriptions.Item label="库内事件数">{fmtInt(d?.ingest?.n_events)}</Descriptions.Item>
              <Descriptions.Item label="已跟踪原始文件">
                {(d?.ingest?.files || []).length} 个
              </Descriptions.Item>
              <Descriptions.Item label="最近事件时间">
                {fmtTs(d?.ingest?.last_event_ts)}
              </Descriptions.Item>
            </Descriptions>
            <div className="muted" style={{ marginTop: 8 }}>
              原始 jsonl 在 <Text code>traindata\proxy\</Text>。入库请调用{' '}
              <Text code>POST /api/ingest/scan</Text>（或重启服务自动扫一次）。
            </div>
          </Card>
        </Col>
      </Row>
    </div>
  )
}
