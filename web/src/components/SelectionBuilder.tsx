import { DatePicker, Form, Input, InputNumber, Radio, Select, Space, Switch, Tag, Typography } from 'antd'
import dayjs from 'dayjs'

const { Text } = Typography

/** 事件筛选条件（与后端 `EventSelectionFilters` 一一对应）。 */
export type EventFilters = {
  action?: string
  method?: string
  status?: number
  ip_list?: string
  src_ip?: string
  path?: string
  q?: string
  min_score?: number
  max_score?: number
  from_ts?: number
  to_ts?: number
  rule_testing?: boolean
  attack_type?: string
  verdict?: string
  rule?: string
  rule_action?: string
  has_rule?: boolean
}

export type SelectionValue = {
  mode: 'ids' | 'filter'
  event_ids?: number[]
  filters: EventFilters
  max_rows?: number
}

export type RuleFacet = { rule: string; name?: string; hits?: number; block_hits?: number }

/** 去掉空串 / undefined，后端只收到真正生效的条件。 */
export function compactFilters(f: EventFilters): EventFilters {
  const out: EventFilters = {}
  for (const [k, v] of Object.entries(f || {})) {
    if (v === undefined || v === null || v === '') continue
    ;(out as any)[k] = v
  }
  return out
}

export const ATTACK_TYPE_OPTIONS = [
  { value: 'sqli', label: 'sqli · SQL 注入' },
  { value: 'xss', label: 'xss · 跨站脚本' },
  { value: 'cmdi', label: 'cmdi · 命令注入' },
  { value: 'traversal', label: 'traversal · 路径穿越' },
  { value: 'normal', label: 'normal · 模型判为正常' },
]

export const VERDICT_OPTIONS = [
  { value: 'any', label: '有任意人工结论' },
  { value: 'none', label: '没有人工结论' },
  { value: 'confirmed_attack', label: '确认攻击' },
  { value: 'false_positive', label: '误报' },
  { value: 'confirmed_benign', label: '确认正常' },
  { value: 'missed', label: '漏报' },
  { value: 'uncertain', label: '待查' },
]

const METHOD_OPTIONS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'].map(
  (v) => ({ value: v, label: v }),
)

type Props = {
  value: SelectionValue
  onChange: (v: SelectionValue) => void
  /** 事件页已勾选多少条（filter 模式不需要）。 */
  selectedCount?: number
  showScope?: boolean
  showMaxRows?: boolean
  ruleOptions?: RuleFacet[]
}

/**
 * 事件 → 训练数据的筛选条件构建器（事件页与数据集页共用）。
 *
 * 为什么不用「只勾选表格行」：表格每页最多 200 条，勾选全选只覆盖当前页。
 * 这里直接按条件筛（上限由后端 `EVENT_DATASET_MAX_ROWS` 控制），勾选只是其中一种模式。
 * 所有条件按 **AND** 组合；标签仍由人工在表单里显式指定。
 */
export default function SelectionBuilder({
  value,
  onChange,
  selectedCount = 0,
  showScope = true,
  showMaxRows = true,
  ruleOptions = [],
}: Props) {
  const f = value.filters || {}
  const patch = (p: Partial<EventFilters>) =>
    onChange({ ...value, filters: compactFilters({ ...f, ...p }) })

  const ruleSelectOptions = (
    ruleOptions.length
      ? ruleOptions
      : []
  ).map((r) => ({
    value: r.rule,
    label: `${r.name || r.rule}${r.hits !== undefined ? `（${r.hits} 次）` : ''}`,
  }))

  return (
    <div>
      {showScope ? (
        <Form.Item label="选择范围" style={{ marginBottom: 12 }}>
          <Radio.Group
            value={value.mode}
            onChange={(e) => onChange({ ...value, mode: e.target.value })}
          >
            <Radio.Button value="ids" disabled={!selectedCount}>
              已勾选 {selectedCount} 条
            </Radio.Button>
            <Radio.Button value="filter">按条件筛选</Radio.Button>
          </Radio.Group>
          <div className="muted" style={{ marginTop: 6, fontSize: 12 }}>
            勾选可跨页保留（后端上限 5000 条）；按条件筛选上限 20000 行。
            表格表头全选只覆盖当前页 —— 要选全部匹配项请用「按条件筛选」。
          </div>
        </Form.Item>
      ) : null}

      {!showScope || value.mode === 'filter' ? (
        <Form layout="vertical" size="small">
          <Space size={4} wrap style={{ marginBottom: 4 }}>
            <Tag color="blue">AND</Tag>
            <Text type="secondary" style={{ fontSize: 12 }}>
              所有条件同时满足才命中；留空表示不限。
            </Text>
          </Space>
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))',
              gap: '0 12px',
            }}
          >
            <Form.Item label="动作">
              <Select
                allowClear
                placeholder="block / alert / allow"
                value={f.action}
                onChange={(v) => patch({ action: v })}
                options={[
                  { value: 'block', label: 'block' },
                  { value: 'alert', label: 'alert' },
                  { value: 'allow', label: 'allow' },
                ]}
              />
            </Form.Item>
            <Form.Item label="方法">
              <Select
                allowClear
                placeholder="GET / POST …"
                value={f.method}
                onChange={(v) => patch({ method: v })}
                options={METHOD_OPTIONS}
              />
            </Form.Item>
            <Form.Item label="状态码">
              <InputNumber
                min={100}
                max={599}
                style={{ width: '100%' }}
                placeholder="例如 200"
                value={f.status}
                onChange={(v) => patch({ status: v === null ? undefined : Number(v) })}
              />
            </Form.Item>
            <Form.Item label="名单">
              <Select
                allowClear
                placeholder="命中 IP 名单"
                value={f.ip_list}
                onChange={(v) => patch({ ip_list: v })}
                options={[
                  { value: 'blacklist', label: '黑名单' },
                  { value: 'whitelist', label: '白名单' },
                ]}
              />
            </Form.Item>
            <Form.Item label="源 IP">
              <Input
                placeholder="精确匹配"
                value={f.src_ip}
                onChange={(e) => patch({ src_ip: e.target.value })}
              />
            </Form.Item>
            <Form.Item label="路径包含">
              <Input
                placeholder="例如 /sql/"
                value={f.path}
                onChange={(e) => patch({ path: e.target.value })}
              />
            </Form.Item>
            <Form.Item label="关键字（路径/查询/UA）">
              <Input
                placeholder="例如 union select"
                value={f.q}
                onChange={(e) => patch({ q: e.target.value })}
              />
            </Form.Item>
            <Form.Item label="监督分区间">
              <Space.Compact style={{ width: '100%' }}>
                <InputNumber
                  min={0}
                  max={1}
                  step={0.05}
                  style={{ width: '50%' }}
                  placeholder="min"
                  value={f.min_score}
                  onChange={(v) => patch({ min_score: v === null ? undefined : Number(v) })}
                />
                <InputNumber
                  min={0}
                  max={1}
                  step={0.05}
                  style={{ width: '50%' }}
                  placeholder="max"
                  value={f.max_score}
                  onChange={(v) => patch({ max_score: v === null ? undefined : Number(v) })}
                />
              </Space.Compact>
            </Form.Item>
            <Form.Item label="攻击类型（模型预测，仅筛选）">
              <Select
                allowClear
                showSearch
                placeholder="不限"
                value={f.attack_type}
                onChange={(v) => patch({ attack_type: v })}
                options={ATTACK_TYPE_OPTIONS}
              />
            </Form.Item>
            <Form.Item label="人工结论">
              <Select
                allowClear
                placeholder="不限"
                value={f.verdict}
                onChange={(v) => patch({ verdict: v })}
                options={VERDICT_OPTIONS}
              />
            </Form.Item>
            <Form.Item label="命中规则">
              <Select
                allowClear
                showSearch
                placeholder={ruleSelectOptions.length ? '选择规则 id' : '暂无规则命中数据'}
                value={f.rule}
                onChange={(v) => patch({ rule: v })}
                options={ruleSelectOptions}
                optionFilterProp="label"
              />
            </Form.Item>
            <Form.Item label="规则动作">
              <Select
                allowClear
                placeholder="不限"
                value={f.rule_action}
                onChange={(v) => patch({ rule_action: v })}
                options={[
                  { value: 'block', label: 'block' },
                  { value: 'alert', label: 'alert' },
                ]}
              />
            </Form.Item>
            <Form.Item label="是否有规则命中">
              <Select
                allowClear
                placeholder="不限"
                value={f.has_rule === true ? 'yes' : f.has_rule === false ? 'no' : undefined}
                onChange={(v) =>
                  patch({ has_rule: v === 'yes' ? true : v === 'no' ? false : undefined })
                }
                options={[
                  { value: 'yes', label: '有命中' },
                  { value: 'no', label: '没有任何规则命中' },
                ]}
              />
            </Form.Item>
            <Form.Item label="时间范围">
              <DatePicker.RangePicker
                showTime
                style={{ width: '100%' }}
                value={[
                  f.from_ts ? dayjs(f.from_ts) : null,
                  f.to_ts ? dayjs(f.to_ts) : null,
                ] as any}
                onChange={(v: any) =>
                  patch({
                    from_ts: v?.[0]?.valueOf(),
                    to_ts: v?.[1]?.valueOf(),
                  })
                }
              />
            </Form.Item>
          </div>
          <Form.Item label="只看测试命中（未合格规则）" style={{ marginBottom: 0 }}>
            <Switch
              size="small"
              checked={!!f.rule_testing}
              onChange={(v) => patch({ rule_testing: v ? true : undefined })}
            />
          </Form.Item>
        </Form>
      ) : null}

      {showMaxRows ? (
        <Form.Item
          label="条数上限"
          style={{ marginTop: 12, marginBottom: 0 }}
          extra="超过上限会按时间倒序截断；后端硬上限 20000。"
        >
          <InputNumber
            min={1}
            max={20000}
            style={{ width: 180 }}
            placeholder="默认 20000"
            value={value.max_rows}
            onChange={(v) => onChange({ ...value, max_rows: v === null ? undefined : Number(v) })}
          />
        </Form.Item>
      ) : null}
    </div>
  )
}