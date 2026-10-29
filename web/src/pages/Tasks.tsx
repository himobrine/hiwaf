import { useCallback, useEffect, useRef, useState } from 'react'
import {
  Alert,
  Button,
  Card,
  Modal,
  Select,
  Space,
  Table,
  Tag,
  Typography,
  message,
} from 'antd'
import { PlayCircleOutlined, ReloadOutlined } from '@ant-design/icons'
import { api, fmtTs } from '../api'
import type { User } from '../types'

const { Title, Text } = Typography

const KINDS = [
  { value: 'train_realdata', label: 'XGBoost 真实数据训练（官方配方）' },
  { value: 'iforest_csic', label: 'IForest（CSIC）' },
  { value: 'iforest_local', label: 'IForest（本地良性）' },
  { value: 'calibrate_csic', label: '阈值重标定（CSIC）' },
  { value: 'export_testvec', label: '导出 testvec' },
  { value: 'export_shap_ref', label: '导出 SHAP 参考' },
  { value: 'export_feature_names', label: '导出特征名' },
  { value: 'p8_e2e', label: 'P8 采集面端到端' },
  { value: 'p4_local', label: 'P4 本机真实流量回归' },
]

const TRAIN_CHANNEL: Record<string, string> = {
  train_realdata: 'supervised',
  iforest_csic: 'zero_day',
  iforest_local: 'zero_day',
}

const INHERIT_OPTIONS = [
  { value: 'warm_start', label: 'warm_start（从父代继续训练，追加树）' },
  { value: 'lineage', label: 'lineage（不 warm start，仅记录父代）' },
  { value: 'off', label: 'off（不继承）' },
]

const STATUS_COLOR: Record<string, string> = {
  queued: 'default',
  running: 'processing',
  ok: 'green',
  failed: 'red',
}

export default function Tasks({ user }: { user: User }) {
  const isAdmin = user.role === 'admin'
  const [items, setItems] = useState<any[]>([])
  const [kind, setKind] = useState('p8_e2e')
  const [err, setErr] = useState('')
  const [loading, setLoading] = useState(false)
  const [pageSize, setPageSize] = useState(20)
  const [logFor, setLogFor] = useState<any>(null)
  const [log, setLog] = useState('')
  const [inherit, setInherit] = useState('warm_start')
  const [parentId, setParentId] = useState<number | undefined>(undefined)
  const [parents, setParents] = useState<Record<string, any[]>>({})
  const [datasets, setDatasets] = useState<any[]>([])
  const [dataMode, setDataMode] = useState('official')
  const [datasetIds, setDatasetIds] = useState<number[]>([])
  const [calibMode, setCalibMode] = useState('auto')
  const timer = useRef<any>(null)

  const load = useCallback(async () => {
    setLoading(true)
    setErr('')
    try {
      const r = await api<any>('/api/tasks?limit=100')
      setItems(r.items || [])
    } catch (e: any) {
      setErr(e?.message || '加载失败')
    } finally {
      setLoading(false)
    }
  }, [])

  const channel = TRAIN_CHANNEL[kind]
  const parentOptions = (channel ? parents[channel] || [] : []).map((m: any) => ({
    value: m.id,
    label: `g${m.generation} · ${m.display_name}（sha ${m.sha1_16}）`,
  }))
  const readyDatasets = datasets.filter(
    (d) => d.status === 'ready' && (channel !== 'zero_day' || d.role !== 'eval'),
  )
  const datasetOptions = readyDatasets.map((d: any) => ({
    value: d.id,
    label:
      `#${d.id} ${d.name} · ${d.origin === 'events' ? '事件' : '上传'} · ${d.role} · ` +
      `${d.rows_kept ?? 0} 行` +
      (d.sha256 ? ` · ${String(d.sha256).slice(0, 8)}` : ''),
  }))
  const calibOptions = datasetOptions

  useEffect(() => {
    api<any>('/api/models')
      .then((d) => setParents(d.parents || {}))
      .catch(() => undefined)
    api<any>('/api/uploads?limit=200')
      .then((d) => setDatasets(d.items || []))
      .catch(() => undefined)
  }, [])

  useEffect(() => {
    setParentId(undefined)
    setDataMode('official')
    setDatasetIds([])
    setCalibMode('auto')
  }, [kind])

  useEffect(() => {
    load()
  }, [load])

  useEffect(() => {
    if (!logFor) return
    let alive = true
    const tick = async () => {
      try {
        const r = await api<any>(`/api/tasks/${logFor.id}/log?tail=400`)
        if (!alive) return
        setLog(r.log || '')
        if (r.status === 'ok' || r.status === 'failed') {
          load()
          if (timer.current) {
            clearInterval(timer.current)
            timer.current = null
          }
        }
      } catch {
        /* ignore */
      }
    }
    tick()
    timer.current = setInterval(tick, 2000)
    return () => {
      alive = false
      if (timer.current) {
        clearInterval(timer.current)
        timer.current = null
      }
    }
  }, [logFor, load])

  const create = async () => {
    try {
      const body: any = { kind }
      if (channel) {
        body.inherit = inherit
        if (parentId) body.parent_model_id = parentId
        if (dataMode !== 'official' && datasetIds.length) {
          body.data_mode = dataMode
          body.dataset_ids = datasetIds
          body.calib_mode = calibMode
        }
      }
      const r = await api<any>('/api/tasks', { method: 'POST', body })
      message.success(
        `任务 #${r.id} 已排队` +
          (r.staging ? `；产物将写入 staging 并在成功后登记为 g 新一代` : ''),
      )
      load()
      setLogFor({ id: r.id })
      setLog('')
    } catch (e: any) {
      message.error(e?.message || '创建失败')
    }
  }

  return (
    <div>
      <div className="toolbar">
        <Title level={4} className="page-title">
          训练任务
        </Title>
        <Select style={{ width: 320 }} value={kind} onChange={setKind} options={KINDS} />
        {channel ? (
          <>
            <Select
              style={{ width: 280 }}
              value={inherit}
              onChange={setInherit}
              options={INHERIT_OPTIONS}
            />
            <Select
              style={{ width: 300 }}
              value={parentId}
              onChange={setParentId}
              allowClear
              placeholder="父代模型（默认现役）"
              options={parentOptions}
            />
            <Select
              style={{ width: 220 }}
              value={dataMode}
              onChange={(v) => {
                setDataMode(v)
                if (v === 'official') setDatasetIds([])
              }}
              options={[
                { value: 'official', label: '数据来源：内置基线' },
                { value: 'add', label: '内置基线 + 数据集（增量）' },
                { value: 'only', label: '仅数据集（替换基线）' },
              ]}
            />
            {dataMode !== 'official' ? (
              <>
                <Select
                  mode="multiple"
                  style={{ minWidth: 320 }}
                  value={datasetIds}
                  onChange={setDatasetIds}
                  placeholder="选择数据集（可多选）"
                  options={datasetOptions}
                />
                <Select
                  style={{ width: 200 }}
                  value={calibMode}
                  onChange={setCalibMode}
                  options={[
                    { value: 'auto', label: '校准池：自动' },
                    { value: 'official', label: '校准池：官方' },
                    { value: 'upload', label: '校准池：数据集留出' },
                  ]}
                />
              </>
            ) : null}
          </>
        ) : null}
        <Button
          type="primary"
          icon={<PlayCircleOutlined />}
          onClick={create}
          disabled={!isAdmin || (!!dataMode && dataMode !== 'official' && datasetIds.length === 0)}
        >
          新建任务
        </Button>
        <Button icon={<ReloadOutlined />} onClick={load} loading={loading}>
          刷新
        </Button>
        {!isAdmin ? <span className="muted">需要 admin</span> : null}
      </div>

      <Alert
        type="warning"
        showIcon
        style={{ marginBottom: 12 }}
        message="任务只接受服务端白名单脚本，不接受任意命令/参数。"
        description="训练产物写入 artifacts/staging/task_<id>/，成功后自动登记为新一代；要上线必须去「模型」页走切换（含门禁）并重启采集器。训练不会直接覆盖现役模型。"
      />
      {channel && dataMode === 'only' ? (
        <Alert
          type="warning"
          showIcon
          style={{ marginBottom: 12 }}
          message="仅数据集模式：内置基线不参与，官方 test/lexical 仅作迁移评估"
          description="only 模式会强制 lineage（不做 warm start）；零日通道要求数据集 ≥400 条良性且能切出 ≥200 条校准留出。"
        />
      ) : null}
      {kind === 'iforest_local' && dataMode === 'add' ? (
        <Alert
          type="info"
          showIcon
          style={{ marginBottom: 12 }}
          message="IForest（本地良性）增量训练"
          description="第一个含良性样本的数据集会作为本地基线（--benign，训练/校准留出从它切）；其余数据集作为增量良性行合并进训练集，并写入训练指纹。"
        />
      ) : null}
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
            pageSizeOptions: ['10', '20', '50', '100'],
            onShowSizeChange: (_p, ps) => setPageSize(ps),
          }}
          columns={[
            { title: 'ID', dataIndex: 'id', width: 70 },
            { title: '类型', dataIndex: 'kind', width: 190 },
            {
              title: '状态',
              dataIndex: 'status',
              width: 100,
              render: (v: string) => <Tag color={STATUS_COLOR[v] || 'default'}>{v}</Tag>,
            },
            { title: '创建', dataIndex: 'created_at', width: 170, render: (v) => fmtTs(v) },
            { title: '结束', dataIndex: 'ended_at', width: 170, render: (v) => fmtTs(v) },
            { title: '退出码', dataIndex: 'exit_code', width: 90 },
            { title: '操作人', dataIndex: 'actor', width: 120 },
            {
              title: '日志',
              width: 100,
              render: (_: any, r: any) => (
                <Button
                  size="small"
                  onClick={() => {
                    setLogFor(r)
                    setLog('')
                  }}
                >
                  查看
                </Button>
              ),
            },
          ]}
        />
      </Card>

      <Modal
        open={!!logFor}
        width={900}
        title={logFor ? `任务 #${logFor.id} · ${logFor.kind}` : ''}
        onCancel={() => setLogFor(null)}
        footer={<Button onClick={() => setLogFor(null)}>关闭</Button>}
      >
        <pre className="pre-wrap">{log || '(暂无输出)'}</pre>
        <div className="muted">
          <Text code>2s</Text> 轮询；任务结束自动停止。日志文件在{' '}
          <Text code>python\service\logs\</Text>。
        </div>
      </Modal>
    </div>
  )
}
