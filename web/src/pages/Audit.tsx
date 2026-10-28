import { useCallback, useEffect, useState } from 'react'
import {
  Alert,
  Button,
  Card,
  Descriptions,
  Input,
  InputNumber,
  Modal,
  Space,
  Table,
  Tag,
  Typography,
  message,
} from 'antd'
import { ClearOutlined, DeleteOutlined, ReloadOutlined } from '@ant-design/icons'
import { api, fmtTs } from '../api'

const { Title, Text } = Typography

export default function Audit() {
  const [items, setItems] = useState<any[]>([])
  const [err, setErr] = useState('')
  const [loading, setLoading] = useState(false)
  const [pageSize, setPageSize] = useState(50)
  const [selectedRowKeys, setSelectedRowKeys] = useState<(string | number)[]>([])

  const [retentionOpen, setRetentionOpen] = useState(false)
  const [retentionDays, setRetentionDays] = useState(90)
  const [preview, setPreview] = useState<any>(null)
  const [previewLoading, setPreviewLoading] = useState(false)
  const [applying, setApplying] = useState(false)

  const [selectedOpen, setSelectedOpen] = useState(false)
  const [reason, setReason] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    setErr('')
    try {
      const r = await api<any>('/api/audit?limit=500')
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

  const loadPreview = async (days: number) => {
    setPreviewLoading(true)
    try {
      const r = await api<any>(`/api/audit/retention?days=${days}`)
      setPreview(r)
    } catch (e: any) {
      message.error(e?.message || '预览失败')
    } finally {
      setPreviewLoading(false)
    }
  }

  const openRetention = () => {
    setRetentionDays(90)
    setPreview(null)
    setRetentionOpen(true)
    loadPreview(90)
  }

  const applyRetention = async () => {
    if (!preview) return
    setApplying(true)
    try {
      const r = await api<any>('/api/audit/retention', {
        method: 'POST',
        body: { days: retentionDays, confirm: true },
      })
      message.success(`已清理 ${r.deleted ?? 0} 条审计记录`)
      setRetentionOpen(false)
      setPreview(null)
      setSelectedRowKeys([])
      load()
    } catch (e: any) {
      message.error(e?.message || '清理失败')
    } finally {
      setApplying(false)
    }
  }

  const applySelected = async () => {
    if (!selectedRowKeys.length) return
    setApplying(true)
    try {
      const r = await api<any>('/api/audit/delete', {
        method: 'POST',
        body: {
          ids: selectedRowKeys.map((x) => Number(x)),
          confirm: true,
          reason: reason || undefined,
        },
      })
      message.success(`已删除 ${r.deleted ?? 0} 条审计记录`)
      setSelectedOpen(false)
      setReason('')
      setSelectedRowKeys([])
      load()
    } catch (e: any) {
      message.error(e?.message || '删除失败')
    } finally {
      setApplying(false)
    }
  }

  return (
    <div>
      <div className="toolbar">
        <Title level={4} className="page-title">
          审计
        </Title>
        <Button
          danger
          icon={<DeleteOutlined />}
          disabled={!selectedRowKeys.length}
          onClick={() => {
            setReason('')
            setSelectedOpen(true)
          }}
        >
          删除选中{selectedRowKeys.length ? `（${selectedRowKeys.length}）` : ''}
        </Button>
        <Button icon={<ClearOutlined />} onClick={openRetention}>
          清理旧审计
        </Button>
        <Button icon={<ReloadOutlined />} onClick={load} loading={loading}>
          刷新
        </Button>
      </div>

      <Alert
        type="info"
        showIcon
        style={{ marginBottom: 12 }}
        message="登录、策略提升、零日开关、规则启停、反馈、body 查看、任务创建与入库扫描都会留痕。"
        description="审计日志默认保留 90 天：系统每日自动清理，admin 也可手动预览/立即清理。删除操作本身会留下 audit_cleanup 记录。"
      />
      {err ? <Alert type="error" message={err} showIcon style={{ marginBottom: 12 }} /> : null}

      <Card size="small">
        <Table
          size="small"
          rowKey="id"
          loading={loading}
          dataSource={items}
          rowSelection={{
            selectedRowKeys,
            preserveSelectedRowKeys: true,
            onChange: (keys) => setSelectedRowKeys(keys as (string | number)[]),
          }}
          pagination={{
            pageSize,
            showSizeChanger: true,
            pageSizeOptions: ['20', '50', '100', '200'],
            onShowSizeChange: (_p, ps) => setPageSize(ps),
            showTotal: (n) => `共 ${n} 条`,
          }}
          columns={[
            { title: '时间', dataIndex: 'ts', width: 180, render: (v) => fmtTs(v) },
            { title: '操作人', dataIndex: 'actor', width: 130 },
            {
              title: '动作',
              dataIndex: 'action',
              width: 190,
              render: (v: string) => <Tag>{v}</Tag>,
            },
            { title: '对象', dataIndex: 'target', width: 220, ellipsis: true },
            { title: '详情', dataIndex: 'detail', ellipsis: true },
            { title: 'IP', dataIndex: 'ip', width: 130 },
          ]}
        />
      </Card>
      <div className="muted" style={{ marginTop: 8 }}>
        列表只显示最近 500 条；清理按完整 audit 表统计。默认保留 90 天，删除为硬删除、不可恢复。
      </div>

      <Modal
        open={retentionOpen}
        title="清理旧审计"
        width={680}
        onCancel={() => setRetentionOpen(false)}
        footer={[
          <Button key="cancel" onClick={() => setRetentionOpen(false)}>
            取消
          </Button>,
          <Button
            key="preview"
            onClick={() => loadPreview(retentionDays)}
            loading={previewLoading}
          >
            预览
          </Button>,
          <Button
            key="apply"
            danger
            type="primary"
            loading={applying}
            disabled={previewLoading || !preview || Number(preview.delete_count) <= 0}
            onClick={applyRetention}
          >
            确认删除 {preview?.delete_count ?? 0} 条
          </Button>,
        ]}
      >
        <Alert
          type="warning"
          showIcon
          style={{ marginBottom: 12 }}
          message="硬删除，不可恢复"
          description="只删除截止时间之前的审计记录；删除动作会写入一条新的 audit_cleanup 记录。"
        />
        <Space style={{ marginBottom: 12 }}>
          <span>保留最近</span>
          <InputNumber
            min={1}
            max={3650}
            value={retentionDays}
            onChange={(v) => setRetentionDays(Number(v || 90))}
            addonAfter="天"
            style={{ width: 140 }}
          />
          <Button onClick={() => loadPreview(retentionDays)} loading={previewLoading}>
            重新预览
          </Button>
        </Space>
        {preview ? (
          <>
            <Descriptions
              size="small"
              column={2}
              bordered
              items={[
                { key: 'total', label: '总记录', children: preview.total },
                { key: 'del', label: '待删除', children: preview.delete_count },
                { key: 'keep', label: '保留', children: preview.keep_count },
                {
                  key: 'auto',
                  label: '自动清理',
                  children: preview.auto_enabled ? '每日' : '已关闭',
                },
                {
                  key: 'cutoff',
                  label: '截止时间',
                  children: fmtTs(preview.cutoff_ms),
                },
                {
                  key: 'range',
                  label: '待删范围',
                  children:
                    preview.delete_oldest_ts != null
                      ? `${fmtTs(preview.delete_oldest_ts)} ~ ${fmtTs(preview.delete_newest_ts)}`
                      : '-',
                },
              ]}
            />
            <div style={{ marginTop: 10 }}>
              <Text type="secondary">待删动作分布：</Text>
              <div style={{ marginTop: 4 }}>
                {preview.by_action?.length ? (
                  preview.by_action.map((x: any) => (
                    <Tag key={x.action} style={{ marginBottom: 4 }}>
                      {x.action}: {x.n}
                    </Tag>
                  ))
                ) : (
                  <Text type="secondary">无</Text>
                )}
              </div>
            </div>
          </>
        ) : null}
      </Modal>

      <Modal
        open={selectedOpen}
        title={`删除选中的 ${selectedRowKeys.length} 条审计`}
        onCancel={() => setSelectedOpen(false)}
        onOk={applySelected}
        okText="确认删除"
        okButtonProps={{ danger: true, loading: applying }}
        confirmLoading={applying}
      >
        <Alert
          type="warning"
          showIcon
          style={{ marginBottom: 12 }}
          message="硬删除，不可恢复"
          description="删除后会写入一条 audit_cleanup_selected 记录，包含删除原因和 id 列表。"
        />
        <Input.TextArea
          rows={2}
          maxLength={500}
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          placeholder="删除原因（可选，会写入审计）"
        />
      </Modal>
    </div>
  )
}
