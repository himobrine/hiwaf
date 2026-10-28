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
  Table,
  Tag,
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

export default function Datasets({ user }: { user: User }) {
  const isAdmin = user.role === 'admin'
  const [items, setItems] = useState<any[]>([])
  const [err, setErr] = useState('')
  const [loading, setLoading] = useState(false)
  const [file, setFile] = useState<any>(null)
  const [preview, setPreview] = useState<any>(null)
  const [submitting, setSubmitting] = useState(false)
  const [form] = Form.useForm()
  const timer = useRef<any>(null)

  const load = useCallback(async () => {
    setLoading(true)
    setErr('')
    try {
      const r = await api<any>('/api/uploads?limit=200')
      setItems(r.items || [])
    } catch (e: any) {
      setErr(e?.message || '加载失败')
    } finally {
      setLoading(false)
    }
  }, [])

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
      message.success('已删除（软删除）')
      load()
    } catch (e: any) {
      message.error(e?.message || '删除失败')
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
          <Card size="small" title="已上传数据集">
            {err ? <Alert type="error" message={err} showIcon style={{ marginBottom: 8 }} /> : null}
            <Table
              size="small"
              rowKey="id"
              loading={loading}
              dataSource={items}
              pagination={{ pageSize: 10, showSizeChanger: false }}
              columns={[
                { title: 'ID', dataIndex: 'id', width: 60 },
                { title: '名称', dataIndex: 'name', ellipsis: true },
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
                  width: 140,
                  render: (_: any, r: any) => (
                    <Space size={4}>
                      <Button size="small" onClick={() => openPreview(r)} disabled={r.status !== 'ready'}>
                        预览
                      </Button>
                      {isAdmin ? (
                        <Popconfirm title="删除该数据集？" onConfirm={() => remove(r)}>
                          <Button size="small" danger icon={<DeleteOutlined />} disabled={r.status === 'pruned'} />
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
    </div>
  )
}
