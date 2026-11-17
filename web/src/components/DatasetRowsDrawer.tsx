import { useCallback, useEffect, useState } from 'react'
import { Alert, Button, Drawer, Input, Select, Space, Table, Tag, Tooltip, Typography, message } from 'antd'
import { api } from '../api'

const { Text } = Typography

const LABEL_OPTIONS = [
  { value: 0, label: '0 · normal（良性）' },
  { value: 1, label: '1 · sqli' },
  { value: 2, label: '2 · xss' },
  { value: 3, label: '3 · cmdi' },
  { value: 4, label: '4 · traversal' },
]

const LABEL_COLOR: Record<number, string> = {
  0: 'green',
  1: 'red',
  2: 'orange',
  3: 'purple',
  4: 'blue',
}

type Props = {
  uid: number | null
  dataset?: any
  open: boolean
  onClose: () => void
  onSaved?: () => void
}

/**
 * 逐条查看 / 修正数据集标签。
 *
 * 保存会原子重写 `requests.jsonl` 并重建训练副本（`requests_train.jsonl`）、
 * 标签统计与文件指纹；正在被任务使用的数据集会被后端拒绝。
 */
export default function DatasetRowsDrawer({ uid, dataset, open, onClose, onSaved }: Props) {
  const [rows, setRows] = useState<any[]>([])
  const [total, setTotal] = useState(0)
  const [offset, setOffset] = useState(0)
  const [limit] = useState(50)
  const [labelFilter, setLabelFilter] = useState<number | undefined>(undefined)
  const [q, setQ] = useState('')
  const [loading, setLoading] = useState(false)
  const [err, setErr] = useState('')
  const [edits, setEdits] = useState<Record<string, number>>({})
  const [saving, setSaving] = useState(false)

  const load = useCallback(async () => {
    if (!uid) return
    setLoading(true)
    setErr('')
    try {
      const p = new URLSearchParams()
      p.set('offset', String(offset))
      p.set('limit', String(limit))
      if (labelFilter !== undefined) p.set('label', String(labelFilter))
      if (q.trim()) p.set('q', q.trim())
      const r = await api<any>(`/api/uploads/${uid}/rows?${p.toString()}`)
      setRows(r.items || [])
      setTotal(Number(r.total || 0))
    } catch (e: any) {
      setErr(e?.message || '加载失败')
    } finally {
      setLoading(false)
    }
  }, [uid, offset, limit, labelFilter, q])

  useEffect(() => {
    if (open) load()
  }, [open, load])

  useEffect(() => {
    if (!open) return
    setOffset(0)
    setEdits({})
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [uid, open])

  const nEdits = Object.keys(edits).length

  const save = async () => {
    if (!uid || !nEdits) return
    setSaving(true)
    try {
      const updates = Object.entries(edits).map(([rid, label]) => ({ rid, label }))
      await api(`/api/uploads/${uid}/rows`, {
        method: 'PATCH',
        body: { updates, note: '数据集逐条修正标签' },
      })
      message.success(`已保存 ${updates.length} 处标签修改，训练副本已重建`)
      setEdits({})
      await load()
      onSaved?.()
    } catch (e: any) {
      message.error(e?.message || '保存失败')
    } finally {
      setSaving(false)
    }
  }

  const benign = dataset?.role === 'benign'
  const canEdit = dataset?.status === 'ready'

  return (
    <Drawer
      open={open}
      width={1080}
      onClose={onClose}
      destroyOnClose
      title={dataset ? `样本与标签 · #${dataset.id} ${dataset.name}` : '样本与标签'}
      extra={
        <Space>
          <Text type="secondary">{total.toLocaleString()} 行</Text>
          <Button
            type="primary"
            loading={saving}
            disabled={!canEdit || !nEdits}
            onClick={save}
          >
            保存修改{nEdits ? `（${nEdits}）` : ''}
          </Button>
        </Space>
      }
    >
      {err ? <Alert type="error" showIcon message={err} style={{ marginBottom: 8 }} /> : null}
      {benign ? (
        <Alert
          type="warning"
          showIcon
          style={{ marginBottom: 8 }}
          message="良性数据集只允许标签 0"
          description="role=benign 的行全部按良性计入训练/校准；改成非 0 会被后端拒绝（避免把良性样本当攻击）。"
        />
      ) : null}
      <Alert
        type="info"
        showIcon
        style={{ marginBottom: 8 }}
        message="保存会重建训练副本"
        description="修改写回 requests.jsonl 后，会重新生成 requests_train.jsonl（剔除与官方评估集重叠的行）、更新标签统计与文件指纹。正在被任务使用的数据集会被拒绝，请先等任务结束。"
      />
      <Space wrap style={{ marginBottom: 8 }}>
        <Select
          allowClear
          placeholder="按标签筛"
          style={{ width: 180 }}
          value={labelFilter}
          onChange={(v) => {
            setOffset(0)
            setLabelFilter(v)
            setEdits({})
          }}
          options={LABEL_OPTIONS}
        />
        <Input.Search
          allowClear
          placeholder="搜路径 / 查询 / body"
          style={{ width: 260 }}
          onSearch={(v) => {
            setOffset(0)
            setQ(v)
          }}
        />
        <Button
          onClick={() => {
            setOffset(0)
            setLabelFilter(undefined)
            setQ('')
            setEdits({})
          }}
        >
          重置
        </Button>
        <Button disabled={offset <= 0} onClick={() => setOffset(Math.max(0, offset - limit))}>
          上一页
        </Button>
        <Button
          disabled={offset + limit >= total}
          onClick={() => setOffset(offset + limit)}
        >
          下一页
        </Button>
        <Text type="secondary">
          {total ? `${offset + 1}–${Math.min(offset + limit, total)} / ${total}` : '—'}
        </Text>
      </Space>
      <Table
        size="small"
        rowKey="rid"
        loading={loading}
        dataSource={rows}
        pagination={false}
        scroll={{ x: 980 }}
        columns={[
          { title: '方法', dataIndex: 'method', width: 72 },
          { title: '路径', dataIndex: 'path', width: 240, ellipsis: true },
          { title: '查询', dataIndex: 'query', width: 220, ellipsis: true },
          {
            title: 'body（预览）',
            dataIndex: 'body_preview',
            ellipsis: true,
            render: (v: string, r: any) =>
              v ? (
                <Tooltip title={v} placement="topLeft">
                  <span>{v}</span>
                </Tooltip>
              ) : (
                <span className="muted">-</span>
              ),
          },
          {
            title: '当前标签',
            dataIndex: 'label',
            width: 90,
            render: (v: number) => <Tag color={LABEL_COLOR[v] || 'default'}>{v}</Tag>,
          },
          {
            title: '改为',
            width: 190,
            render: (_: any, r: any) => (
              <Select
                size="small"
                style={{ width: 170 }}
                value={edits[r.rid] !== undefined ? edits[r.rid] : r.label}
                disabled={!canEdit}
                onChange={(v) => {
                  setEdits((prev) => {
                    const next = { ...prev }
                    if (v === r.label) delete next[r.rid]
                    else next[r.rid] = v
                    return next
                  })
                }}
                options={benign ? LABEL_OPTIONS.filter((o) => o.value === 0) : LABEL_OPTIONS}
              />
            ),
          },
          {
            title: '来源',
            dataIndex: 'label_why',
            width: 200,
            ellipsis: true,
            render: (v: string) => <span className="muted">{v || '-'}</span>,
          },
        ]}
      />
    </Drawer>
  )
}