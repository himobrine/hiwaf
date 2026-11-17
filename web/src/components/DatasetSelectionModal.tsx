import { useCallback, useEffect, useState } from 'react'
import {
  Alert,
  Button,
  Descriptions,
  InputNumber,
  Modal,
  Radio,
  Select,
  Space,
  Typography,
  message,
} from 'antd'
import { api } from '../api'
import SelectionBuilder, { compactFilters, type RuleFacet, type SelectionValue } from './SelectionBuilder'

const { Text } = Typography

const LABEL_OPTIONS = [
  { value: 0, label: '0 · normal（良性）' },
  { value: 1, label: '1 · sqli' },
  { value: 2, label: '2 · xss' },
  { value: 3, label: '3 · cmdi' },
  { value: 4, label: '4 · traversal' },
]

type Props = {
  dataset: any
  open: boolean
  onClose: () => void
  onDone: () => void
  ruleOptions?: RuleFacet[]
}

/**
 * 给已就绪数据集追加事件或按新条件重采样。
 *
 * append：按请求指纹去重后追加，已有行标签不动（逐条修正不会被覆盖）。
 * replace：整体重建，会覆盖逐条修正，必须二次确认。
 */
export default function DatasetSelectionModal({
  dataset,
  open,
  onClose,
  onDone,
  ruleOptions = [],
}: Props) {
  const [action, setAction] = useState<'append' | 'replace'>('append')
  const [label, setLabel] = useState<number>(1)
  const [sel, setSel] = useState<SelectionValue>({ mode: 'filter', filters: {} })
  const [preview, setPreview] = useState<any>(null)
  const [previewing, setPreviewing] = useState(false)
  const [submitting, setSubmitting] = useState(false)

  useEffect(() => {
    if (!open) return
    setAction('append')
    setLabel(dataset?.default_label ?? 1)
    setSel({ mode: 'filter', filters: {} })
    setPreview(null)
  }, [open, dataset])

  const filters = compactFilters(sel.filters)

  const doPreview = useCallback(async () => {
    if (!Object.keys(filters).length) {
      message.warning('至少填一个筛选条件')
      return
    }
    setPreviewing(true)
    setPreview(null)
    try {
      const body: any = { mode: 'filter', filters }
      if (sel.max_rows) body.max_rows = sel.max_rows
      setPreview(await api<any>('/api/events/selection-preview', { method: 'POST', body }))
    } catch (e: any) {
      message.error(e?.message || '预检失败')
    } finally {
      setPreviewing(false)
    }
  }, [filters, sel.max_rows])

  // 条件变化后自动预检（防抖 500ms），让操作员立刻看到命中量。
  useEffect(() => {
    if (!open) return
    if (!Object.keys(filters).length) {
      setPreview(null)
      return
    }
    const t = setTimeout(() => {
      void doPreview()
    }, 500)
    return () => clearTimeout(t)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, JSON.stringify(filters), sel.max_rows])

  const doSubmit = async () => {
    if (!dataset?.id) return
    if (!Object.keys(filters).length) {
      message.warning('至少填一个筛选条件')
      return
    }
    setSubmitting(true)
    try {
      const body: any = {
        action,
        mode: 'filter',
        filters,
        label,
      }
      if (sel.max_rows) body.max_rows = sel.max_rows
      const r = await api<any>(`/api/uploads/${dataset.id}/selection`, {
        method: 'POST',
        body,
      })
      message.success(
        `${action === 'append' ? '已追加' : '已重采样'}：数据集现在 ${Number(
          r?.rows_kept || 0,
        ).toLocaleString()} 行`,
      )
      onDone()
      onClose()
    } catch (e: any) {
      message.error(e?.message || '提交失败')
    } finally {
      setSubmitting(false)
    }
  }

  const submit = () => {
    if (action === 'replace') {
      Modal.confirm({
        title: '重采样会覆盖现有行与逐条修正',
        content:
          '会删除该数据集当前的 requests.jsonl 内容，用新条件重新生成；已有的逐条标签修正会丢失（保留一份 requests.prev.jsonl 备份）。确定继续吗？',
        okText: '确认重采样',
        okType: 'danger',
        cancelText: '取消',
        onOk: doSubmit,
      })
      return
    }
    void doSubmit()
  }

  return (
    <Modal
      open={open}
      width={820}
      title={dataset ? `追加 / 重采样 · #${dataset.id} ${dataset.name}` : '追加 / 重采样'}
      onCancel={onClose}
      onOk={submit}
      okText={action === 'append' ? '追加到数据集' : '重采样'}
      okButtonProps={{ danger: action === 'replace' }}
      confirmLoading={submitting}
      styles={{ body: { maxHeight: '62vh', overflowY: 'auto', paddingRight: 4 } }}
    >
      <Alert
        type="info"
        showIcon
        style={{ marginBottom: 12 }}
        message="标签仍由你显式指定"
        description="事件的 attack_type 是模型预测，只用于筛选；新行统一使用下面选择的标签（良性数据集只能选 0）。"
      />
      <Space direction="vertical" size={4} style={{ marginBottom: 8 }}>
        <Radio.Group value={action} onChange={(e) => setAction(e.target.value)}>
          <Radio.Button value="append">追加（保留已有行）</Radio.Button>
          <Radio.Button value="replace">重采样（整体重建）</Radio.Button>
        </Radio.Group>
        <Text type="secondary" style={{ fontSize: 12 }}>
          当前 {Number(dataset?.rows_kept || 0).toLocaleString()} 行；
          {action === 'append'
            ? '新行按请求指纹去重后追加，已有行标签不变。'
            : '会覆盖现有行与逐条修正（保留 requests.prev.jsonl 备份）。'}
        </Text>
      </Space>

      <Space wrap style={{ marginBottom: 8 }}>
        <span>新行标签：</span>
        <Select
          style={{ width: 220 }}
          value={label}
          onChange={setLabel}
          options={dataset?.role === 'benign' ? LABEL_OPTIONS.filter((o) => o.value === 0) : LABEL_OPTIONS}
        />
        <span className="muted">条数上限</span>
        <InputNumber
          min={1}
          max={20000}
          placeholder="默认 20000"
          value={sel.max_rows}
          onChange={(v) => setSel({ ...sel, max_rows: v === null ? undefined : Number(v) })}
        />
      </Space>

      <SelectionBuilder
        value={sel}
        onChange={setSel}
        selectedCount={0}
        showScope={false}
        showMaxRows={false}
        ruleOptions={ruleOptions}
      />

      {preview ? (
        <Descriptions size="small" column={2} bordered style={{ marginTop: 8 }}>
          <Descriptions.Item label="匹配事件">{preview.matched}</Descriptions.Item>
          <Descriptions.Item label="上限 / 截断">
            {preview.limit} / {preview.truncated ? '会截断' : '不截断'}
          </Descriptions.Item>
          <Descriptions.Item label="抽查 / 去重后">
            {preview.checked} / {preview.unique_checked}
          </Descriptions.Item>
          <Descriptions.Item label="body 缺失">
            {preview.body?.missing ?? 0}
          </Descriptions.Item>
        </Descriptions>
      ) : null}
      <Space style={{ marginTop: 8 }}>
        <Button onClick={doPreview} loading={previewing}>
          预检
        </Button>
        <Text type="secondary" style={{ fontSize: 12 }}>
          条件变化后会自动预检一次。
        </Text>
      </Space>
    </Modal>
  )
}