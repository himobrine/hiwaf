import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  Alert,
  Button,
  Card,
  Checkbox,
  Col,
  Descriptions,
  Divider,
  Input,
  Modal,
  Popconfirm,
  Row,
  Select,
  Space,
  Table,
  Tabs,
  Tag,
  Tooltip,
  Typography,
  message,
} from 'antd'
import {
  ExportOutlined,
  ReloadOutlined,
  RollbackOutlined,
  SwapOutlined,
} from '@ant-design/icons'
import ReactEChartsCore from 'echarts-for-react/lib/core'
import echarts from '../echarts'
import { api, fmtBytes, fmtInt, fmtNum, fmtTs } from '../api'
import type { User } from '../types'

const { Title, Text, Paragraph } = Typography

const CHANNEL_LABEL: Record<string, string> = {
  supervised: '监督通道（XGBoost）',
  zero_day: '零日通道（IForest）',
}

const STATE_COLOR: Record<string, string> = {
  in_sync: 'green',
  pending_restart: 'orange',
  disk_mismatch: 'red',
  model_missing: 'red',
  unregistered: 'blue',
  collector_unknown: 'default',
}

const STATE_LABEL: Record<string, string> = {
  in_sync: '已生效',
  pending_restart: '待重启采集器',
  disk_mismatch: '磁盘与策略不一致',
  model_missing: '模型文件缺失',
  unregistered: '未登记',
  collector_unknown: '无法确认（采集器未上报 / 纯采集）',
}

const MODEL_STATUS_COLOR: Record<string, string> = {
  active: 'green',
  candidate: 'blue',
  archived: 'default',
  pruned: 'red',
}

const MODEL_STATUS_LABEL: Record<string, string> = {
  active: '现役',
  candidate: '候选',
  archived: '历史',
  pruned: '已清理',
}

const LINEAGE_STATUS_COLOR: Record<string, string> = {
  active: '#52c41a',
  candidate: '#1677ff',
  archived: '#8c8c8c',
  pruned: '#ff4d4f',
}

/** 子代相对父代「继承了什么」——和训练任务里的 inherit_mode 同一套取值。 */
const INHERIT_LABEL: Record<string, string> = {
  warm_start: 'warm start（从父代继续训练）',
  lineage: '仅记录血缘（父代不参与训练）',
  off: '不继承（无父代记录）',
  full: '默认（自动挂到当时的现役）',
}

/**
 * 代际传承树：父代在上、子代在下，一个通道一棵树。
 * 节点颜色 = 状态；蓝色连线 = 现役这条血脉；空心虚线 = 元数据仍在但快照已清理。
 */
function lineageOption(payload: any) {
  const pathSet = new Set<number>(payload?.path_to_current || [])
  const currentId = payload?.current_id ?? null

  const toNode = (n: any): any => {
    const color = LINEAGE_STATUS_COLOR[n.status] || '#8c8c8c'
    const onPath = pathSet.has(n.id)
    const isCurrent = n.id === currentId
    return {
      id: String(n.id),
      name: `g${n.generation}`,
      raw: n,
      symbol: 'circle',
      symbolSize: isCurrent ? 16 : 12,
      itemStyle: {
        color: n.status === 'pruned' ? '#fff' : color,
        borderColor: n.status === 'pruned' ? '#ff4d4f' : color,
        borderWidth: n.status === 'pruned' ? 2 : isCurrent ? 3 : 1,
        borderType: n.status === 'pruned' ? 'dashed' : 'solid',
      },
      // 现役血脉用蓝色连线标出（比给节点描边更不容易和「候选=蓝」混淆）。
      lineStyle: onPath ? { color: '#0958d9', width: 2.6 } : undefined,
      children: (n.children || []).map(toNode),
    }
  }

  const nodes = (payload?.tree || []).map(toNode)
  // 多根（历史断档 / 脏数据降级）时加一个通道虚拟根，保证是一棵可渲染的树。
  const data =
    nodes.length > 1
      ? [
          {
            id: '__channel__',
            name: payload?.channel === 'zero_day' ? '零日通道' : '监督通道',
            raw: null,
            symbolSize: 1,
            itemStyle: { color: 'transparent', borderWidth: 0 },
            label: { show: false },
            children: nodes,
          },
        ]
      : nodes

  return {
    tooltip: {
      trigger: 'item',
      formatter: (p: any) => {
        const n = p.data?.raw
        if (!n) return String(p.name ?? '')
        const rows = [
          `<b>${n.display_name || `第 ${n.generation} 代`}</b>`,
          `代次：g${n.generation}`,
          `状态：${MODEL_STATUS_LABEL[n.status] || n.status}`,
          `sha1-16：<code>${n.sha1_16 ?? '-'}</code>`,
          `继承：${INHERIT_LABEL[n.inherit_mode] || n.inherit_mode || '-'}`,
          n.snapshot_available ? '快照：可用（可切换 / 可作为父代）' : '快照：缺失（仅元数据）',
          '<span style="color:#888">点击查看该代详情</span>',
        ]
        return rows.join('<br/>')
      },
    },
    series: [
      {
        type: 'tree',
        data,
        top: 26,
        left: 60,
        right: 60,
        bottom: 56,
        orient: 'TB',
        symbol: 'circle',
        initialTreeDepth: -1,
        expandAndCollapse: false,
        animationDuration: 300,
        animationDurationUpdate: 300,
        lineStyle: { color: '#bfbfbf', width: 1.4, curveness: 0.4 },
        emphasis: { focus: 'ancestor' },
        label: {
          position: 'bottom',
          align: 'center',
          verticalAlign: 'top',
          distance: 6,
          fontSize: 11,
          lineHeight: 15,
          width: 76,
          overflow: 'break',
          formatter: (p: any) => {
            const n = p.data?.raw
            if (!n) return p.name ?? ''
            const tag = MODEL_STATUS_LABEL[n.status] || n.status
            // 兄弟节点间距有限，节点上只放代次 + 状态；模型名/继承方式看悬停或下方表格。
            return `g${n.generation}\n${tag}`
          },
        },
      },
    ],
  }
}

function curveOption(series: Record<string, number[][]> | undefined) {
  const keys = Object.keys(series || {})
  return {
    legend: { type: 'scroll', top: 0 },
    tooltip: { trigger: 'axis' },
    grid: { left: 60, right: 24, top: 44, bottom: 40 },
    xAxis: { type: 'value', name: 'round / trees' },
    yAxis: { type: 'value', scale: true },
    series: keys.map((k) => ({
      name: k,
      type: 'line',
      showSymbol: false,
      data: (series?.[k] || []).map((p: number[]) => [p[0], p[1]]),
    })),
  }
}

export default function Models({ user }: { user: User }) {
  const isAdmin = user.role === 'admin'
  const canEdit = user.role === 'admin' || user.role === 'analyst'

  const [data, setData] = useState<any>(null)
  const [err, setErr] = useState('')
  const [loading, setLoading] = useState(false)

  const [channel, setChannel] = useState('supervised')
  const [curveData, setCurveData] = useState<any>(null)
  const [curveLabel, setCurveLabel] = useState('')
  const [legacyCurve, setLegacyCurve] = useState<string | undefined>(undefined)
  const [legacyCurveData, setLegacyCurveData] = useState<any>(null)

  const [editModel, setEditModel] = useState<any>(null)
  const [editName, setEditName] = useState('')
  const [editNotes, setEditNotes] = useState('')

  const [preflight, setPreflight] = useState<any>(null)
  const [switchModel, setSwitchModel] = useState<any>(null)
  const [switchBusy, setSwitchBusy] = useState(false)

  const [settings, setSettings] = useState<any>(null)

  const [lineagePick, setLineagePick] = useState<any>(null)
  const [lineageDetail, setLineageDetail] = useState<any>(null)

  const load = useCallback(async () => {
    setLoading(true)
    setErr('')
    try {
      const d = await api<any>('/api/models')
      setData(d)
      setSettings(d.settings)
      if (!legacyCurve && d.curves?.length) {
        const prefer = d.curves.find((c: string) => c.includes('realdata_v2'))
        setLegacyCurve(prefer || d.curves[0])
      }
    } catch (e: any) {
      setErr(e?.message || '加载失败')
    } finally {
      setLoading(false)
    }
  }, [legacyCurve])

  useEffect(() => {
    load()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  useEffect(() => {
    if (!legacyCurve) return
    let alive = true
    api<any>(`/api/models/curves/${encodeURIComponent(legacyCurve)}`)
      .then((d) => alive && setLegacyCurveData(d))
      .catch((e: any) => alive && setErr(e?.message || '曲线加载失败'))
    return () => {
      alive = false
    }
  }, [legacyCurve])

  const models: any[] = data?.models || []
  const current = data?.current
  const lineage = data?.lineage?.channels?.[channel]
  const byChannel = useMemo(() => {
    const m: Record<string, any[]> = { supervised: [], zero_day: [] }
    for (const x of models) (m[x.channel] ||= []).push(x)
    return m
  }, [models])

  const openCurve = async (m: any) => {
    try {
      const d = await api<any>(`/api/models/${m.id}/curve`)
      setCurveData(d)
      setCurveLabel(`g${m.generation} · ${m.display_name}`)
    } catch (e: any) {
      message.error(e?.message || '该模型没有学习曲线')
    }
  }

  const pickLineageNode = async (n: any) => {
    setLineagePick(n)
    setLineageDetail(null)
    try {
      setLineageDetail(await api<any>(`/api/models/${n.id}`))
    } catch (e: any) {
      message.error(e?.message || '加载该代详情失败')
    }
  }

  const saveEdit = async () => {
    if (!editModel) return
    try {
      await api(`/api/models/${editModel.id}`, {
        method: 'PATCH',
        body: { display_name: editName, notes: editNotes },
      })
      message.success('已保存')
      setEditModel(null)
      load()
    } catch (e: any) {
      message.error(e?.message || '保存失败')
    }
  }

  const startSwitch = async (m: any) => {
    try {
      const pf = await api<any>(`/api/models/${m.id}/preflight`, { method: 'POST' })
      setPreflight(pf)
      setSwitchModel(m)
    } catch (e: any) {
      message.error(e?.message || '预检失败')
    }
  }

  const doSwitch = async () => {
    if (!switchModel) return
    setSwitchBusy(true)
    try {
      const r = await api<any>(`/api/models/${switchModel.id}/switch`, {
        method: 'POST',
        body: { confirm: true },
      })
      message.success(`切换任务 #${r.task_id} 已启动；成功后必须重启采集器`)
      setPreflight(null)
      setSwitchModel(null)
      load()
    } catch (e: any) {
      message.error(e?.message || '切换失败')
    } finally {
      setSwitchBusy(false)
    }
  }

  const rollback = async (ch: string) => {
    try {
      const r = await api<any>(`/api/models/rollback/${ch}`, { method: 'POST' })
      message.success(`回滚任务 #${r.task_id} 已启动`)
      load()
    } catch (e: any) {
      message.error(e?.message || '回滚失败')
    }
  }

  const saveSettings = async () => {
    try {
      const r = await api<any>('/api/models/settings', { method: 'PUT', body: settings })
      setSettings(r.settings)
      message.success('保留策略已保存')
      load()
    } catch (e: any) {
      message.error(e?.message || '保存失败')
    }
  }

  const doPrune = async (dry: boolean) => {
    try {
      const r = await api<any>('/api/models/prune', {
        method: 'POST',
        body: { dry_run: dry },
      })
      const n = r.models?.length || 0
      message.success(`${dry ? '预演' : '清理'}：${n} 个模型${dry ? '将被清理' : '已清理'}`)
      if (!dry) load()
    } catch (e: any) {
      message.error(e?.message || '操作失败')
    }
  }

  const registerLive = async () => {
    try {
      const r = await api<any>('/api/models/register-live', { method: 'POST' })
      message.success(`已登记 ${r.registered?.length || 0} 个现役模型`)
      load()
    } catch (e: any) {
      message.error(e?.message || '登记失败')
    }
  }

  const currentCard = (ch: string) => {
    const c = current?.channels?.[ch]
    if (!c) return null
    const m = c.model
    return (
      <Card
        size="small"
        title={
          <Space>
            <span>{CHANNEL_LABEL[ch]}</span>
            <Tag color={STATE_COLOR[c.state] || 'default'}>
              {STATE_LABEL[c.state] || c.state}
            </Tag>
          </Space>
        }
        extra={
          isAdmin ? (
            <Space>
              <Popconfirm
                title="回滚到上一代现役模型？"
                description="回滚同样走完整门禁，成功后需重启采集器。"
                onConfirm={() => rollback(ch)}
              >
                <Button size="small" icon={<RollbackOutlined />}>
                  回滚上一代
                </Button>
              </Popconfirm>
            </Space>
          ) : null
        }
      >
        <Descriptions
          size="small"
          column={1}
          items={[
            { key: 'name', label: '现役模型', children: m ? m.display_name : '（未登记）' },
            {
              key: 'gen',
              label: '代次',
              children: m ? `g${m.generation}（id=${m.id}）` : '-',
            },
            {
              key: 'sha',
              label: '策略记录 sha1-16',
              children: <Text code>{c.policy_sha1_16 || '-'}</Text>,
            },
            {
              key: 'dsha',
              label: '磁盘文件 sha1-16',
              children: <Text code>{c.disk_sha1_16 || '-'}</Text>,
            },
            {
              key: 'csha',
              label: '采集器已加载 sha1-16',
              children: <Text code>{c.collector_sha1_16 || '（未上报）'}</Text>,
            },
            {
              key: 'thr',
              label: '阈值 / 目标 FPR',
              children: `${fmtNum(c.threshold, 6)} @ ${c.target_fpr ?? '-'}`,
            },
            {
              key: 'ver',
              label: '策略版本',
              children: `v${c.policy_version ?? '-'}`,
            },
          ]}
        />
        {c.state === 'pending_restart' ? (
          <Alert
            style={{ marginTop: 8 }}
            type="warning"
            showIcon
            message="磁盘上的模型比采集器内存里的新 —— 必须重启采集器，新模型才生效。"
          />
        ) : null}
      </Card>
    )
  }

  const columns = [
    {
      title: '代次',
      dataIndex: 'generation',
      width: 80,
      render: (v: number, r: any) => (
        <Space size={4}>
          <Text>g{v}</Text>
          {r.is_current ? <Tag color="green">现役</Tag> : null}
        </Space>
      ),
    },
    {
      title: '名称 / 备注',
      dataIndex: 'display_name',
      render: (v: string, r: any) => (
        <div>
          <div>{v}</div>
          {r.notes ? <div className="muted">{r.notes}</div> : null}
          <Text code style={{ fontSize: 11 }}>
            {r.sha1_16}
          </Text>
        </div>
      ),
    },
    {
      title: '状态',
      dataIndex: 'status',
      width: 90,
      render: (v: string) => <Tag color={MODEL_STATUS_COLOR[v]}>{MODEL_STATUS_LABEL[v] || v}</Tag>,
    },
    {
      title: '血缘',
      width: 150,
      render: (_: any, r: any) => (
        <div className="muted" style={{ fontSize: 12 }}>
          <div>父代：{r.parent_id ?? '-'}</div>
          <div>继承：{r.inherit_mode || '-'}</div>
        </div>
      ),
    },
    {
      title: '训练数据',
      width: 180,
      render: (_: any, r: any) => {
        const ds = (r.recipe || {}).datasets
        const up = (r.recipe || {}).upload
        if (!ds || !ds.length) return <span className="muted">官方配方</span>
        return (
          <div className="muted" style={{ fontSize: 12 }}>
            <div>{up?.mode === 'only' ? '仅上传' : '官方 + 上传'}</div>
            {ds.map((d: any) => (
              <div key={d.id} title={d.sha256 || ''}>
                #{d.id} {d.name}（{d.rows ?? '-'} 行）
              </div>
            ))}
          </div>
        )
      },
    },
    {
      title: '指标',
      width: 220,
      render: (_: any, r: any) => {
        const mt = r.metrics || {}
        if (r.channel === 'supervised') {
          const t = mt.test || {}
          const lx = mt.lexical || {}
          return (
            <div className="muted" style={{ fontSize: 12 }}>
              <div>树数：{fmtInt(mt.n_trees)}</div>
              <div>TEST acc {fmtNum(t.accuracy)} / AUC {fmtNum(t.auc_binary)}</div>
              <div>LEXICAL acc {fmtNum(lx.accuracy)} / AUC {fmtNum(lx.auc_binary)}</div>
            </div>
          )
        }
        const det = mt.detect || {}
        return (
          <div className="muted" style={{ fontSize: 12 }}>
            <div>树数：{fmtInt(mt.trees)}</div>
            <div>@1% 检出 {det['0.01'] != null ? `${(det['0.01'] * 100).toFixed(1)}%` : '-'}</div>
            <div>max_samples {fmtInt(mt.max_samples)}</div>
          </div>
        )
      },
    },
    { title: '大小', dataIndex: 'bytes', width: 90, render: (v: number) => fmtBytes(v) },
    { title: '创建', dataIndex: 'created_at', width: 160, render: (v: number) => fmtTs(v) },
    {
      title: '操作',
      width: 230,
      render: (_: any, r: any) => (
        <Space size={4} wrap>
          {canEdit ? (
            <Button
              size="small"
              onClick={() => {
                setEditModel(r)
                setEditName(r.display_name)
                setEditNotes(r.notes || '')
              }}
            >
              改名/备注
            </Button>
          ) : null}
          {r.curve_available ? (
            <Button size="small" onClick={() => openCurve(r)}>
              曲线
            </Button>
          ) : null}
          {isAdmin && r.status !== 'pruned' && r.snapshot_available ? (
            <Tooltip title={r.is_current ? '已是现役；切换会重跑门禁' : '切换为现役模型'}>
              <Button
                size="small"
                type="primary"
                ghost
                icon={<SwapOutlined />}
                onClick={() => startSwitch(r)}
              >
                切换
              </Button>
            </Tooltip>
          ) : null}
        </Space>
      ),
    },
  ]

  return (
    <div>
      <div className="toolbar">
        <Title level={4} className="page-title">
          模型与门禁
        </Title>
        <Button icon={<ReloadOutlined />} onClick={load} loading={loading}>
          刷新
        </Button>
        {isAdmin ? (
          <Button onClick={registerLive} icon={<ExportOutlined />}>
            登记现役产物
          </Button>
        ) : null}
      </div>

      {err ? <Alert type="error" message={err} showIcon style={{ marginBottom: 12 }} /> : null}

      <Row gutter={[12, 12]}>
        <Col xs={24} lg={12}>
          {currentCard('supervised')}
        </Col>
        <Col xs={24} lg={12}>
          {currentCard('zero_day')}
        </Col>
      </Row>

      <Card size="small" style={{ marginTop: 12 }} title="模型代际与传承">
        <Tabs
          activeKey={channel}
          onChange={setChannel}
          items={[
            { key: 'supervised', label: `监督通道（${byChannel.supervised.length}）` },
            { key: 'zero_day', label: `零日通道（${byChannel.zero_day.length}）` },
          ]}
        />

        {!data ? (
          <div className="muted" style={{ padding: 24, textAlign: 'center' }}>
            加载模型登记…
          </div>
        ) : lineage && lineage.n ? (
          <>
            <ReactEChartsCore
              echarts={echarts}
              option={lineageOption(lineage)}
              onEvents={{
                click: (p: any) => {
                  const n = p?.data?.raw
                  if (n) pickLineageNode(n)
                },
              }}
              style={{
                height: Math.max(190, Math.min(560, 150 + (lineage.stats?.depth ?? 0) * 90)),
              }}
              notMerge
            />
            <Space size={14} wrap className="muted" style={{ fontSize: 12, marginTop: 2 }}>
              {(['active', 'candidate', 'archived', 'pruned'] as const).map((s) => (
                <span key={s}>
                  <span
                    style={{
                      display: 'inline-block',
                      width: 8,
                      height: 8,
                      borderRadius: 4,
                      marginRight: 4,
                      background: LINEAGE_STATUS_COLOR[s],
                    }}
                  />
                  {MODEL_STATUS_LABEL[s]}
                </span>
              ))}
              <span>蓝色连线 = 现役这条血脉</span>
              <span>空心虚线 = 快照已清理（只留元数据与血缘）</span>
            </Space>
            <div className="muted" style={{ fontSize: 12, marginTop: 4 }}>
              共 {lineage.n} 代 · 血缘边 {lineage.stats?.edges ?? 0} 条（其中 warm start{' '}
              {lineage.stats?.warm_start_edges ?? 0} 条）· 最大代次 g{lineage.max_generation}
              {' · '}由上到下 = 父代 → 子代；悬停看模型名与继承方式，点击看该代详情
            </div>
            {(lineage.orphans || []).length ? (
              <Tooltip
                title={(lineage.orphans || [])
                  .map(
                    (o: any) =>
                      `id=${o.id}：${
                        ({ missing: '父代不存在', self: '父代是自己', cycle: '父子成环' } as Record<
                          string,
                          string
                        >)[o.reason] || o.reason
                      }（parent_id=${o.parent_id}）`,
                  )
                  .join('；')}
              >
                <Tag color="orange" style={{ marginTop: 6 }}>
                  {lineage.orphans.length} 个节点父代缺失 / 成环，已按根展示
                </Tag>
              </Tooltip>
            ) : null}
          </>
        ) : (
          <div className="muted" style={{ padding: 24, textAlign: 'center' }}>
            该通道还没有登记模型。训练完成并登记（或点「登记现役产物」）后，这里会画出父子传承。
          </div>
        )}

        <Divider style={{ margin: '12px 0' }} />

        <Table
          size="small"
          rowKey="id"
          pagination={false}
          dataSource={byChannel[channel] || []}
          columns={columns as any}
        />
        <div className="muted" style={{ marginTop: 8 }}>
          血缘来自登记时的 <Text code>parent_id</Text>：<Text code>warm_start</Text>{' '}
          表示这一代是从父代继续训练出来的；<Text code>lineage</Text>{' '}
          只记录血缘、父代不参与训练。被保留策略清理的模型（状态「已清理」）只保留元数据与曲线，
          用于血缘与历史对比，不能切换 / 继承。
        </div>
      </Card>

      <Row gutter={[12, 12]} style={{ marginTop: 12 }}>
        <Col xs={24} lg={14}>
          <Card
            size="small"
            title="学习曲线"
            extra={
              <Select
                size="small"
                style={{ width: 340 }}
                value={legacyCurve}
                onChange={setLegacyCurve}
                showSearch
                options={(data?.curves || []).map((c: string) => ({ value: c, label: c }))}
              />
            }
          >
            <Tabs
              size="small"
              items={[
                {
                  key: 'registry',
                  label: curveLabel ? `模型曲线 · ${curveLabel}` : '模型曲线',
                  children: curveData ? (
                    <ReactEChartsCore
                      echarts={echarts}
                      option={curveOption(curveData.series)}
                      style={{ height: 300 }}
                      notMerge
                    />
                  ) : (
                    <div className="muted" style={{ padding: 40, textAlign: 'center' }}>
                      在模型表里点「曲线」查看某一代的学习曲线（可跨代对比）。
                    </div>
                  ),
                },
                {
                  key: 'legacy',
                  label: '曲线库',
                  children: legacyCurveData ? (
                    <ReactEChartsCore
                      echarts={echarts}
                      option={curveOption(legacyCurveData.series)}
                      style={{ height: 300 }}
                      notMerge
                    />
                  ) : (
                    <div className="muted" style={{ padding: 40, textAlign: 'center' }}>
                      选择一条曲线
                    </div>
                  ),
                },
              ]}
            />
          </Card>
        </Col>

        <Col xs={24} lg={10}>
          <Card size="small" title="保留策略（双上限）">
            {settings ? (
              <Space direction="vertical" style={{ width: '100%' }}>
                <div>
                  <Text>每通道最多保留（含现役）</Text>
                  <Input
                    type="number"
                    value={settings.max_per_channel}
                    disabled={!isAdmin}
                    onChange={(e) =>
                      setSettings({ ...settings, max_per_channel: Number(e.target.value) })
                    }
                  />
                </div>
                <div>
                  <Text>全局最多保留（含现役）</Text>
                  <Input
                    type="number"
                    value={settings.max_total}
                    disabled={!isAdmin}
                    onChange={(e) => setSettings({ ...settings, max_total: Number(e.target.value) })}
                  />
                </div>
                <div>
                  <Text>训练默认继承</Text>
                  <Select
                    style={{ width: '100%' }}
                    value={settings.inherit_mode}
                    disabled={!isAdmin}
                    onChange={(v) => setSettings({ ...settings, inherit_mode: v })}
                    options={[
                      { value: 'off', label: '不继承（仅记录血缘）' },
                      { value: 'lineage', label: 'lineage（记录父代，不 warm start）' },
                      { value: 'warm_start', label: 'warm_start（从父代继续训练）' },
                    ]}
                  />
                </div>
                <Space>
                  <Checkbox
                    checked={settings.auto_register}
                    disabled={!isAdmin}
                    onChange={(e) =>
                      setSettings({ ...settings, auto_register: e.target.checked })
                    }
                  >
                    训练完成自动登记
                  </Checkbox>
                  <Checkbox
                    checked={settings.keep_curves}
                    disabled={!isAdmin}
                    onChange={(e) => setSettings({ ...settings, keep_curves: e.target.checked })}
                  >
                    清理时保留曲线
                  </Checkbox>
                </Space>
                <Paragraph className="muted" style={{ marginBottom: 0 }}>
                  现役模型永不清理，实际保存数可能略超上限。被清理的模型保留元数据行以维持血缘。
                </Paragraph>
                <Space>
                  <Button type="primary" disabled={!isAdmin} onClick={saveSettings}>
                    保存
                  </Button>
                  <Button disabled={!isAdmin} onClick={() => doPrune(true)}>
                    预演清理
                  </Button>
                  <Popconfirm title="确认按保留策略清理模型快照？" onConfirm={() => doPrune(false)}>
                    <Button danger disabled={!isAdmin}>
                      执行清理
                    </Button>
                  </Popconfirm>
                </Space>
              </Space>
            ) : null}
          </Card>
        </Col>
      </Row>

      <Card size="small" title="切换 / 回滚记录" style={{ marginTop: 12 }}>
        <SwitchesTable />
      </Card>

      <Modal
        open={!!editModel}
        title={`编辑模型 g${editModel?.generation ?? ''}`}
        onCancel={() => setEditModel(null)}
        onOk={saveEdit}
        okText="保存"
      >
        <div style={{ marginBottom: 8 }}>
          <Text>名称</Text>
          <Input value={editName} onChange={(e) => setEditName(e.target.value)} maxLength={64} />
        </div>
        <div>
          <Text>备注</Text>
          <Input.TextArea
            value={editNotes}
            onChange={(e) => setEditNotes(e.target.value)}
            rows={4}
            maxLength={2000}
          />
        </div>
      </Modal>

      <Modal
        open={!!lineagePick}
        title={
          lineagePick
            ? `第 ${lineagePick.generation} 代 · ${lineagePick.display_name ?? ''}`
            : ''
        }
        footer={null}
        onCancel={() => setLineagePick(null)}
        width={680}
      >
        {lineagePick ? (
          <>
            <Descriptions
              size="small"
              column={2}
              bordered
              items={[
                {
                  key: 'status',
                  label: '状态',
                  children: (
                    <Tag color={MODEL_STATUS_COLOR[lineagePick.status]}>
                      {MODEL_STATUS_LABEL[lineagePick.status] || lineagePick.status}
                    </Tag>
                  ),
                },
                {
                  key: 'inherit',
                  label: '继承方式',
                  children: INHERIT_LABEL[lineagePick.inherit_mode] || lineagePick.inherit_mode || '-',
                },
                {
                  key: 'sha',
                  label: 'sha1-16',
                  children: <Text code>{lineagePick.sha1_16 || '-'}</Text>,
                },
                {
                  key: 'snap',
                  label: '快照',
                  children: lineagePick.snapshot_available ? (
                    <Tag color="green">可用</Tag>
                  ) : (
                    <Tag color="red">缺失（仅元数据）</Tag>
                  ),
                },
                {
                  key: 'created',
                  label: '登记时间',
                  children: fmtTs(lineagePick.created_at),
                },
                {
                  key: 'active',
                  label: '激活 / 退役',
                  children: `${lineagePick.activated_at ? fmtTs(lineagePick.activated_at) : '-'} / ${
                    lineagePick.retired_at ? fmtTs(lineagePick.retired_at) : '-'
                  }`,
                },
              ]}
            />
            {lineageDetail ? (
              <div style={{ marginTop: 12 }}>
                <Text strong>血缘</Text>
                <div className="muted" style={{ marginTop: 4 }}>
                  {[...(lineageDetail.lineage || [])]
                    .reverse()
                    .map((a: any) => `g${a.generation}`)
                    .concat(`g${lineageDetail.generation}`)
                    .join(' → ')}
                  {lineageDetail.parent_id == null ? '（根：无父代）' : ''}
                </div>
                <div style={{ marginTop: 8 }}>
                  <Text strong>子代</Text>{' '}
                  {(lineageDetail.children || []).length ? (
                    <Space size={4} wrap>
                      {lineageDetail.children.map((c: any) => (
                        <Tag key={c.id}>
                          g{c.generation} {c.display_name}
                        </Tag>
                      ))}
                    </Space>
                  ) : (
                    <span className="muted">无</span>
                  )}
                </div>
                <div style={{ marginTop: 8 }}>
                  <Text strong>切换记录</Text>{' '}
                  <span className="muted">{(lineageDetail.switches || []).length} 条</span>
                  <Space size={4} wrap style={{ marginLeft: 8 }}>
                    {(lineageDetail.switches || []).slice(0, 3).map((s: any) => (
                      <Tag
                        key={s.id}
                        color={s.status === 'ok' ? 'green' : s.status === 'failed' ? 'red' : 'processing'}
                      >
                        #{s.id} {s.status}
                      </Tag>
                    ))}
                  </Space>
                </div>
              </div>
            ) : (
              <div className="muted" style={{ marginTop: 12 }}>
                加载该代详情…
              </div>
            )}
          </>
        ) : null}
      </Modal>

      <Modal
        open={!!preflight}
        title={`切换为现役：${switchModel?.display_name ?? ''}`}
        onCancel={() => {
          setPreflight(null)
          setSwitchModel(null)
        }}
        onOk={doSwitch}
        okText="确认切换（走完整门禁）"
        okButtonProps={{ disabled: !preflight?.ok, loading: switchBusy }}
        width={720}
      >
        <Alert
          type="warning"
          showIcon
          style={{ marginBottom: 12 }}
          message="切换会：写入固定槽位 → 重标定阈值 → 重出 testvec/SHAP → 跑 waf-ai-proto 门禁；任一步失败全量回滚。"
          description="成功后采集器仍用旧模型，必须重启采集器新模型才生效。"
        />
        <Table
          size="small"
          rowKey="name"
          pagination={false}
          dataSource={preflight?.checks || []}
          columns={[
            { title: '检查项', dataIndex: 'name', width: 200 },
            {
              title: '结果',
              dataIndex: 'ok',
              width: 80,
              render: (v: boolean) => (v ? <Tag color="green">通过</Tag> : <Tag color="red">失败</Tag>),
            },
            { title: '说明', dataIndex: 'detail', ellipsis: true },
          ]}
        />
      </Modal>
    </div>
  )
}

function SwitchesTable() {
  const [items, setItems] = useState<any[]>([])
  const [loading, setLoading] = useState(false)
  const load = useCallback(async () => {
    setLoading(true)
    try {
      const r = await api<any>('/api/models/switches?limit=30')
      setItems(r.items || [])
    } catch {
      /* ignore */
    } finally {
      setLoading(false)
    }
  }, [])
  useEffect(() => {
    load()
    const t = setInterval(load, 5000)
    return () => clearInterval(t)
  }, [load])
  return (
    <Table
      size="small"
      rowKey="id"
      loading={loading}
      pagination={false}
      dataSource={items}
      columns={[
        { title: 'ID', dataIndex: 'id', width: 60 },
        { title: '通道', dataIndex: 'channel', width: 110 },
        { title: '目标模型', dataIndex: 'model_id', width: 90 },
        {
          title: '状态',
          dataIndex: 'status',
          width: 90,
          render: (v: string) => (
            <Tag color={v === 'ok' ? 'green' : v === 'failed' ? 'red' : 'processing'}>{v}</Tag>
          ),
        },
        {
          title: '策略版本',
          width: 140,
          render: (_: any, r: any) => `v${r.policy_version_before ?? '-'} → v${r.policy_version_after ?? '-'}`,
        },
        { title: '创建', dataIndex: 'created_at', width: 160, render: (v: number) => fmtTs(v) },
        { title: '错误', dataIndex: 'error', ellipsis: true },
      ]}
    />
  )
}
