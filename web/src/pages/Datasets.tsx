import { useCallback, useEffect, useRef, useState } from 'react'
import {
  Alert,
  Button,
  Card,
  Col,
  Form,
  Input,
  Modal,
  Popconfirm,
  Row,
  Select,
  Space,
  Switch,
  Table,
  Tag,
  Tooltip,
  Typography,
  Upload,
  message,
} from 'antd'
import { DeleteOutlined, InboxOutlined, ReloadOutlined } from '@ant-design/icons'
import { api, apiUpload, fmtBytes, fmtInt, fmtTs } from '../api'
import type { User } from '../types'

const { Title, Text, Paragraph } = Typography

const ROLE_OPTIONS = [
  { value: 'supervised', label: '监督训练（逐行标签，XGBoost）' },
  { value: 'benign', label: '良性样本（零日训练 / 阈值校准）' },
  { value: 'eval', label: '仅评估（不参与训练）' },
]

const LABEL_OPTIONS = [
  { value: 0, label: '0 · normal（良性）' },
  { value: 1, label: '1 · sqli' },
  { value: 2, label: '2 · xss' },
  { value: 3, label: '3 · cmdi' },
  { value: 4, label: '4 · traversal' },
]

const STATUS_COLOR: Record<string, string> = {
  converting: 'processing',
  ready: 'green',
  failed: 'red',
  pruned: 'default',
}

const ROLE_LABEL: Record<string, string> = {
  supervised: '监督训练',
  benign: '良性样本',
  eval: '仅评估',
}

const ORIGIN_LABEL: Record<string, string> = {
  upload: '上传',
  events: '事件选择',
}

/** 事件数据集的来源摘要：勾选了多少条 / 筛选条件是什么。 */
function selectionSummary(r: any): string {
  const s = r?.selection || {}
  if (s.mode === 'ids') {
    const n = (s.event_ids || []).length
    return `勾选 ${n} 条事件`
  }
  const f = s.filters || {}
  const parts = Object.entries(f).map(([k, v]) => `${k}=${v}`)
  return parts.length ? `筛选：${parts.join(' ')}` : '事件筛选'
}

export default function Datasets({ user }: { user: User }) {
  const isAdmin = user.role === 'admin'
  const canEdit = user.role !== 'viewer'
  const [items, setItems] = useState<any[]>([])
  const [err, setErr] = useState('')
  const [loading, setLoading] = useState(false)
  const [file, setFile] = useState<any>(null)
  const [preview, setPreview] = useState<any>(null)
  const [submitting, setSubmitting] = useState(false)
  const [form] = Form.useForm()
  const timer = useRef<any>(null)
  // 编辑（名称 / 来源说明）：角色与标签在生成时固化，不在这里改。
  const [edit, setEdit] = useState<any>(null)
  const [editForm] = Form.useForm()
  const [savingEdit, setSavingEdit] = useState(false)
  const [showPruned, setShowPruned] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    setErr('')
    try {
      const q = `/api/uploads?limit=200${showPruned ? '&include_pruned=1' : ''}`
      const r = await api<any>(q)
      setItems(r.items || [])
    } catch (e: any) {
      setErr(e?.message || '加载失败')
    } finally {
      setLoading(false)
    }
  }, [showPruned])

  useEffect(() => {
    load()
  }, [load])

  // 有 converting 时轮询。
  useEffect(() => {
    if (timer.current) {
      clearInterval(timer.current)
      timer.current = null
    }
    if (items.some((x) => x.status === 'converting')) {
      timer.current = setInterval(load, 3000)
    }
    return () => {
      if (timer.current) {
        clearInterval(timer.current)
        timer.current = null
      }
    }
  }, [items, load])

  const submit = async () => {
    if (!file) {
      message.warning('请先选择文件')
      return
    }
    let v: any
    try {
      v = await form.validateFields()
    } catch {
      return
    }
    const fd = new FormData()
    fd.append('file', file)
    fd.append('name', v.name || file.name)
    fd.append('role', v.role)
    if (v.default_label !== undefined && v.default_label !== null) {
      fd.append('default_label', String(v.default_label))
    }
    fd.append('source_note', v.source_note || '')
    setSubmitting(true)
    try {
      await apiUpload('/api/uploads', fd)
      message.success('上传成功，后台解析中')
      setFile(null)
      form.resetFields()
      load()
    } catch (e: any) {
      message.error(e?.message || '上传失败')
    } finally {
      setSubmitting(false)
    }
  }

  const openPreview = async (row: any) => {
    try {
      const r = await api<any>(`/api/uploads/${row.id}/preview?n=30`)
      setPreview(r)
    } catch (e: any) {
      message.error(e?.message || '预览失败')
    }
  }

  const remove = async (row: any) => {
    try {
      await api(`/api/uploads/${row.id}`, { method: 'DELETE' })
      message.success('已删除（软删除；可在「显示已删除」里确认）')
      load()
    } catch (e: any) {
      message.error(e?.message || '删除失败')
    }
  }

  const openEdit = (row: any) => {
    editForm.setFieldsValue({
      name: row.name,
      source_note: row.source_note || '',
    })
    setEdit(row)
  }

  const saveEdit = async () => {
    let v: any
    try {
      v = await editForm.validateFields()
    } catch {
      return
    }
    setSavingEdit(true)
    try {
      await api(`/api/uploads/${edit.id}`, {
        method: 'PATCH',
        body: { name: v.name, source_note: v.source_note || '' },
      })
      message.success('已保存')
      setEdit(null)
      load()
    } catch (e: any) {
      message.error(e?.message || '保存失败')
    } finally {
      setSavingEdit(false)
    }
  }

  return (
    <div>
      <div className="toolbar">
        <Title level={4} className="page-title">
          训练数据
        </Title>
        <Button icon={<ReloadOutlined />} onClick={load} loading={loading}>
          刷新
        </Button>
        <Space size={4}>
          <Switch size="small" checked={showPruned} onChange={setShowPruned} />
          <span className="muted">显示已删除</span>
        </Space>
      </div>

      <Alert
        type="warning"
        showIcon
        style={{ marginBottom: 12 }}
        message="上传的是原始 HTTP 请求，不是预计算特征"
        description={
          <span>
            CSV 列：<Text code>method,url,path,query,body,label,attack_type</Text>；JSON 可为数组 /
            {' '}<Text code>{'{requests:[...]}'}</Text> / JSONL；pcap/pcapng 只支持<Text strong>明文 HTTP/1.x</Text>
            （TLS/HTTP2 跳过），且只能整份文件一个标签。所有数据由服务端统一抽 80 维特征，
            与线上同源；与官方评估集重叠的样本会在训练时被剔除。
            <br />
            也可以在「事件」页勾选事件（或按筛选全量）直接生成数据集：标签必须人工指定，
            事件的模型预测不会当标签；body 优先取已入库内容，缺失时回退 raw JSONL。
          </span>
        }
      />

      <Row gutter={16}>
        <Col xs={24} lg={10}>
          <Card size="small" title="上传新数据集">
            <Upload.Dragger
              multiple={false}
              maxCount={1}
              accept=".csv,.tsv,.json,.jsonl,.ndjson,.pcap,.pcapng,.cap"
              beforeUpload={(f) => {
                setFile(f)
                if (!form.getFieldValue('name')) form.setFieldValue('name', f.name)
                return false
              }}
              onRemove={() => setFile(null)}
              fileList={file ? [file as any] : []}
            >
              <p className="ant-upload-drag-icon">
                <InboxOutlined />
              </p>
              <p className="ant-upload-text">点击或拖拽文件到此处</p>
              <p className="ant-upload-hint">CSV / JSON / JSONL / pcap / pcapng，单文件 ≤256MB</p>
            </Upload.Dragger>
            <Form form={form} layout="vertical" style={{ marginTop: 12 }} initialValues={{ role: 'supervised' }}>
              <Form.Item name="name" label="名称">
                <Input placeholder="给数据集起个名字" />
              </Form.Item>
              <Form.Item name="role" label="角色" rules={[{ required: true }]}>
                <Select options={ROLE_OPTIONS} />
              </Form.Item>
              <Form.Item
                name="default_label"
                label="默认标签（缺标签 / pcap 整份文件）"
                extra="CSV/JSON 有 label 或 attack_type 时以行内为准"
              >
                <Select allowClear options={LABEL_OPTIONS} placeholder="不设置" />
              </Form.Item>
              <Form.Item
                name="source_note"
                label="数据来源说明"
                rules={[{ required: true, message: '监督/良性数据必须填写出处' }]}
              >
                <Input.TextArea rows={2} placeholder="例如：本机 phpStudy 访问日志；或红队演练 pcap" />
              </Form.Item>
              <Button type="primary" onClick={submit} loading={submitting} disabled={!file}>
                上传并解析
              </Button>
            </Form>
          </Card>
        </Col>

        <Col xs={24} lg={14}>
          <Card size="small" title="数据集（上传 / 事件选择）">
            {err ? <Alert type="error" message={err} showIcon style={{ marginBottom: 8 }} /> : null}
            <Table
              size="small"
              rowKey="id"
              loading={loading}
              dataSource={items}
              pagination={{ pageSize: 10, showSizeChanger: false }}
              columns={[
                { title: 'ID', dataIndex: 'id', width: 60 },
                {
                  title: '名称',
                  dataIndex: 'name',
                  ellipsis: true,
                  render: (v: string, r: any) => (
                    <Tooltip title={r.source_note || ''} placement="topLeft">
                      <span>{v}</span>
                    </Tooltip>
                  ),
                },
                {
                  title: '来源',
                  dataIndex: 'origin',
                  width: 96,
                  render: (v: string, r: any) => (
                    <Tooltip title={r.origin === 'events' ? selectionSummary(r) : r.original_name || ''}>
                      <Tag color={r.origin === 'events' ? 'geekblue' : 'default'}>
                        {ORIGIN_LABEL[r.origin || 'upload'] || r.origin}
                      </Tag>
                    </Tooltip>
                  ),
                },
                {
                  title: '角色',
                  dataIndex: 'role',
                  width: 100,
                  render: (v: string) => ROLE_LABEL[v] || v,
                },
                { title: '格式', dataIndex: 'format', width: 80 },
                {
                  title: '状态',
                  dataIndex: 'status',
                  width: 110,
                  render: (v: string, r: any) => (
                    <Tag color={STATUS_COLOR[v] || 'default'} title={r.error || ''}>
                      {v}
                    </Tag>
                  ),
                },
                {
                  title: '行数',
                  width: 120,
                  render: (_: any, r: any) =>
                    r.status === 'ready'
                      ? `${fmtInt(r.rows_kept)} / ${fmtInt(r.rows_total)}`
                      : '-',
                },
                {
                  title: '标签',
                  width: 170,
                  render: (_: any, r: any) => {
                    const ls = r.label_stats || {}
                    const parts = Object.keys(ls)
                      .sort()
                      .map((k) => `${k}:${ls[k]}`)
                    return parts.length ? <Text style={{ fontSize: 12 }}>{parts.join(' ')}</Text> : '-'
                  },
                },
                { title: '大小', dataIndex: 'size_bytes', width: 90, render: (v: number) => fmtBytes(v) },
                { title: '上传人', dataIndex: 'created_by', width: 90 },
                { title: '时间', dataIndex: 'created_at', width: 160, render: (v: number) => fmtTs(v) },
                {
                  title: '操作',
                  width: 190,
                  render: (_: any, r: any) => (
                    <Space size={4}>
                      <Button size="small" onClick={() => openPreview(r)} disabled={r.status !== 'ready'}>
                        预览
                      </Button>
                      <Button
                        size="small"
                        onClick={() => openEdit(r)}
                        disabled={!canEdit || r.status === 'pruned'}
                      >
                        编辑
                      </Button>
                      {isAdmin ? (
                        <Popconfirm
                          title="删除该数据集？"
                          description={
                            <span>
                              「{r.name}」的目录与文件会一并删除，记录标成 pruned（软删除）。
                              正在转换或正被任务使用的不能删。
                            </span>
                          }
                          okText="删除"
                          okType="danger"
                          onConfirm={() => remove(r)}
                        >
                          <Button
                            size="small"
                            danger
                            icon={<DeleteOutlined />}
                            disabled={r.status === 'pruned' || r.status === 'converting'}
                          />
                        </Popconfirm>
                      ) : null}
                    </Space>
                  ),
                },
              ]}
            />
          </Card>
        </Col>
      </Row>

      <Modal
        open={!!preview}
        width={960}
        title={preview ? `预览 · ${preview.dataset?.name}（前 ${preview.items?.length || 0} 条）` : ''}
        onCancel={() => setPreview(null)}
        footer={<Button onClick={() => setPreview(null)}>关闭</Button>}
      >
        {preview?.dataset?.stats?.overlap_official_eval ? (
          <Alert
            type="info"
            showIcon
            style={{ marginBottom: 8 }}
            message={`与官方评估集重叠 ${preview.dataset.stats.overlap_official_eval.n} 条，训练时已剔除`}
          />
        ) : null}
        {preview?.dataset?.origin === 'events' ? (
          <Alert
            type="info"
            showIcon
            style={{ marginBottom: 8 }}
            message={`来源：事件选择（${selectionSummary(preview.dataset)}）；标签=${preview?.dataset?.default_label ?? '-'}`}
          />
        ) : null}
        {preview?.dataset?.stats?.body?.missing ? (
          <Alert
            type="warning"
            showIcon
            style={{ marginBottom: 8 }}
            message={`有 ${preview.dataset.stats.body.missing} 条拿不到 body（会以空 body 参与训练）`}
          />
        ) : null}
        <Table
          size="small"
          rowKey={(_: any, i?: number) => String(i)}
          dataSource={preview?.items || []}
          pagination={false}
          columns={[
            { title: 'method', dataIndex: 'method', width: 80 },
            { title: 'path', dataIndex: 'path', ellipsis: true },
            { title: 'query', dataIndex: 'query', ellipsis: true },
            { title: 'body', dataIndex: 'body', ellipsis: true },
            { title: 'label', dataIndex: 'label', width: 70 },
          ]}
        />
        {preview?.dataset?.stats ? (
          <Paragraph className="muted" style={{ marginTop: 8 }}>
            <Text code>{JSON.stringify(preview.dataset.stats)}</Text>
          </Paragraph>
        ) : null}
      </Modal>

      <Modal
        open={!!edit}
        title={edit ? `编辑数据集 #${edit.id}` : ''}
        onCancel={() => setEdit(null)}
        onOk={saveEdit}
        okText="保存"
        confirmLoading={savingEdit}
        destroyOnClose
      >
        <Form form={editForm} layout="vertical" preserve={false}>
          <Form.Item
            name="name"
            label="名称"
            rules={[
              { required: true, message: '名称不能为空' },
              { max: 120, message: '名称不能超过 120 字符' },
            ]}
          >
            <Input placeholder="例如：sqlmap 扫描（确认为攻击）" />
          </Form.Item>
          <Form.Item
            name="source_note"
            label="来源说明"
            rules={[{ max: 2000, message: '说明不能超过 2000 字符' }]}
            extra="角色（监督/良性/仅评估）与标签在生成数据集时已固化到文件，这里不能改；要换请重新生成数据集。"
          >
            <Input.TextArea rows={3} maxLength={2000} showCount />
          </Form.Item>
        </Form>
        {edit?.origin === 'events' ? (
          <Alert
            type="info"
            showIcon
            message={`来源：事件选择（${selectionSummary(edit)}）；标签=${edit.default_label ?? '-'}`}
          />
        ) : null}
      </Modal>
    </div>
  )
}
