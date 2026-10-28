import { useCallback, useEffect, useState } from 'react'
import { Alert, Button, Card, Space, Table, Tag, Typography, message } from 'antd'
import { DownloadOutlined, ReloadOutlined } from '@ant-design/icons'
import { api, fmtTs } from '../api'
import type { User } from '../types'

const { Title } = Typography

const VERDICT_COLOR: Record<string, string> = {
  false_positive: 'red',
  missed: 'volcano',
  confirmed_attack: 'green',
  uncertain: 'gold',
}

export default function Feedback({ user }: { user: User }) {
  const [items, setItems] = useState<any[]>([])
  const [err, setErr] = useState('')
  const [loading, setLoading] = useState(false)
  const [pageSize, setPageSize] = useState(50)

  const load = useCallback(async () => {
    setLoading(true)
    setErr('')
    try {
      const r = await api<any>('/api/feedback?limit=500')
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

  const doExport = async () => {
    try {
      const r = await api<any>('/api/feedback/export')
      const blob = new Blob([JSON.stringify(r, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `waf_feedback_${Date.now()}.json`
      a.click()
      URL.revokeObjectURL(url)
      message.success('已导出')
    } catch (e: any) {
      message.error(e?.message || '导出失败')
    }
  }

  return (
    <div>
      <div className="toolbar">
        <Title level={4} className="page-title">
          反馈台账
        </Title>
        <Button icon={<ReloadOutlined />} onClick={load} loading={loading}>
          刷新
        </Button>
        <Button icon={<DownloadOutlined />} onClick={doExport} disabled={user.role === 'viewer'}>
          导出 JSON
        </Button>
      </div>

      <Alert
        type="info"
        showIcon
        style={{ marginBottom: 12 }}
        message="反馈是独立台账：不会覆盖 pred，也不会自动变成训练标签；需人工复核后才可用于构建评估集/训练集。"
      />
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
            pageSizeOptions: ['20', '50', '100', '200'],
            onShowSizeChange: (_p, ps) => setPageSize(ps),
            showTotal: (n) => `共 ${n} 条`,
          }}
          columns={[
            { title: '时间', dataIndex: 'ts', width: 180, render: (v) => fmtTs(v) },
            { title: '事件', dataIndex: 'event_id', width: 90, render: (v) => `#${v}` },
            {
              title: '结论',
              dataIndex: 'verdict',
              width: 140,
              render: (v: string) => <Tag color={VERDICT_COLOR[v] || 'default'}>{v}</Tag>,
            },
            { title: '操作人', dataIndex: 'actor', width: 140 },
            { title: '备注', dataIndex: 'note' },
          ]}
        />
      </Card>
    </div>
  )
}
