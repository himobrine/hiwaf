import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  Alert, Badge, Button, Card, Descriptions, Divider, Drawer, Dropdown, Form, Input, InputNumber,
  Modal, Select, Space, Switch, Table, Tabs, Tag, Tooltip, Typography, message,
} from 'antd'
import {
  CheckCircleOutlined, DeleteOutlined, EditOutlined, ExperimentOutlined, EyeOutlined,
  FireOutlined, PlusOutlined, ReloadOutlined, SafetyCertificateOutlined, SearchOutlined,
  ThunderboltOutlined, UndoOutlined,
} from '@ant-design/icons'
import { api, fmtInt, fmtPct, fmtTs } from '../api'
import type {
  PolicyRules, RuleBreaker, RuleEvidence, RuleIncident, RuleRow, RuleSample, RulesPayload, User,
} from '../types'

const { Title, Text } = Typography

const VERDICT_COLOR: Record<string, string> = {
  keep: 'green',
  reject_fp: 'red',
  reject_no_hit: 'default',
  unverifiable_by_pool: 'gold',
  insufficient: 'orange',
  insufficient_support: 'orange',
}

const SEVERITY_COLOR: Record<string, string> = {
  high: 'red',
  medium: 'gold',
  low: 'default',
}

const STATE_COLOR: Record<string, string> = {
  uncompiled: 'default',
  noisy: 'red',
  testing: 'gold',
  suggest: 'blue',
  qualified: 'green',
}

const STATE_LABEL: Record<string, string> = {
  uncompiled: '草稿（未编译）',
  noisy: '良性有误报',
  ready: '已编译（未启用）',
  testing: '测试中（只告警）',
  suggest: '证据已够（待确认）',
  qualified: '已合格',
}

const REASON_LABEL: Record<string, string> = {
  confirmed_fp: '人工确认误报',
  noise: '告警噪声',
  hit_spike: '命中量突增',
  block_spike: '阻断量突增',
  manual: '手动熔断',
}

const VERDICT_LABEL: Record<string, string> = {
  confirmed_attack: '确认攻击',
  missed: '漏报',
  confirmed_benign: '确认正常',
  false_positive: '误报',
  uncertain: '待查',
}

const ACTION_FILTERS = [
  { text: 'alert', value: 'alert' },
  { text: 'block', value: 'block' },
  { text: '已熔断', value: 'breaker' },
]

const ENABLED_FILTERS = [
  { text: '已启用', value: 'enabled' },
  { text: '未启用', value: 'disabled' },
]

const CUSTOM_STATE_FILTERS = [
  { text: STATE_LABEL.uncompiled, value: 'uncompiled' },
  { text: STATE_LABEL.noisy, value: 'noisy' },
  { text: STATE_LABEL.ready, value: 'ready' },
  { text: STATE_LABEL.testing, value: 'testing' },
  { text: STATE_LABEL.suggest, value: 'suggest' },
  { text: STATE_LABEL.qualified, value: 'qualified' },
  { text: '已熔断', value: 'breaker' },
]

/** 只显示"这条规则的证据到哪一步"的一句话，避免把整段 JSON 倒给用户。 */
function verdictHint(r: RuleRow): string {
  switch (r.verdict) {
    case 'keep':
      return '在真实良性池上零误报，且能命中攻击 —— 有证据，允许阻断。'
    case 'reject_fp':
      return `在真实良性上有实测误报（${fmtInt(r.benign_hits ?? 0)}/${fmtInt(r.benign_n ?? 0)}）—— 可启用，但只告警。`
    case 'unverifiable_by_pool':
      return '现有评估池里没有这类攻击，无法验证它是否真能命中 —— 可启用，但只告警。'
    case 'insufficient':
    case 'insufficient_support':
      return `攻击侧命中只有个位数（${fmtInt(r.attack_hits ?? 0)}/${fmtInt(r.attack_n ?? 0)}），统计上无意义 —— 可启用，但只告警。`
    default:
      return ''
  }
}

function gateOf(r: RuleRow) {
  const v: any = r.validation || {}
  const g = v.gates || {}
  return {
    reg: g.regex_safety || v.regex,
    benign: g.benign_replay || v.benign,
    attack: g.attack_replay || v.attack,
    failedAt: v.failed_at,
  }
}

type MinedFilters = {
  verdict?: string[]
  grade?: string[]
  action?: string[]
  enabled?: string[]
}

type CustomFilters = {
  state?: string[]
  qualified?: string[]
  action?: string[]
  enabled?: string[]
  source?: string[]
  kind?: string[]
  gate?: string[]
}

type IncidentFilters = {
  severity?: string[]
  status?: string[]
  reason?: string[]
}

type BreakerFilters = {
  mode?: string[]
  reason?: string[]
}

type TablePager = { current: number; pageSize: number }

const RULE_PAGE_SIZE_OPTIONS = ['20', '50', '100', '200']
const INCIDENT_PAGE_SIZE_OPTIONS = ['20', '30', '50', '100']

function minedGrade(r: RuleRow): string {
  if (r.verdict === 'keep') return 'proven'
  return r.enabled ? 'override' : 'disabled'
}

function actionKey(r: RuleRow): string {
  return r.breaker ? 'breaker' : (r.action || 'alert')
}

function customStateKey(r: RuleRow): string {
  return r.breaker ? 'breaker' : (r.state || 'testing')
}

function customQualifiedKey(r: RuleRow): string {
  if (r.is_qualified) return 'qualified'
  if (r.suggest_qualified) return 'suggest'
  return 'insufficient'
}

function gateKey(r: RuleRow): string {
  const g = gateOf(r)
  const values = [g.reg, g.benign, g.attack].filter(Boolean)
  if (!values.length) return 'unchecked'
  if (values.some((v: any) => v?.passed === false)) return 'failed'
  return 'passed'
}

function sourceLabel(v: string): string {
  return ({
    wafjson: '规则集导入',
    crs: 'CRS',
    manual: '自撰',
    custom: '自撰',
    mined: '挖出候选',
  } as Record<string, string>)[v] || v || '?'
}

function matchesQuery(q: string, ...values: any[]): boolean {
  const needle = q.trim().toLowerCase()
  if (!needle) return true
  return values.some((v) => String(v ?? '').toLowerCase().includes(needle))
}

function picked(filters: Record<string, any>, key: string): string[] {
  return (filters[key] || []).map((v: any) => String(v))
}

/** 一条规则的状态标签：熔断 > 派生状态。 */
function stateTag(r: RuleRow) {
  if (r.breaker) {
    return (
      <Tooltip title={`被熔断：${r.breaker.reason}（${fmtTs(r.breaker.opened_at)}）`}>
        <Tag color="red" icon={<FireOutlined />}>已熔断</Tag>
      </Tooltip>
    )
  }
  const s = r.state || 'testing'
  return (
    <Tooltip title={(r.blockers || []).join('；')}>
      <Tag color={STATE_COLOR[s] || 'default'}>{STATE_LABEL[s] || s}</Tag>
    </Tooltip>
  )
}

export default function Rules({ user }: { user: User }) {
  const isAdmin = user.role === 'admin'
  const canWrite = user.role !== 'viewer'

  const [data, setData] = useState<RulesPayload | null>(null)
  const [policyRules, setPolicyRules] = useState<PolicyRules | null>(null)
  const [err, setErr] = useState('')
  const [loading, setLoading] = useState(false)
  const [busy, setBusy] = useState<string>('')
  const [tab, setTab] = useState('mined')

  // 自撰规则弹窗
  const [edit, setEdit] = useState<{ mode: 'create' | 'edit'; rule?: RuleRow } | null>(null)
  const [form] = Form.useForm()

  // 提升弹窗
  const [promoteOpen, setPromoteOpen] = useState(false)
  const [promoteForm] = Form.useForm()
  const [preview, setPreview] = useState<any>(null)
  const [promoteRes, setPromoteRes] = useState<any>(null)
  const [promoting, setPromoting] = useState(false)

  // 证据抽屉
  const [evidenceOpen, setEvidenceOpen] = useState(false)
  const [evidence, setEvidence] = useState<RuleEvidence | null>(null)
  const [evidenceLoading, setEvidenceLoading] = useState(false)
  const [evidenceRid, setEvidenceRid] = useState('')

  // 合格确认
  const [qualify, setQualify] = useState<RuleRow | null>(null)
  const [qualifyForm] = Form.useForm()
  const [historyDays, setHistoryDays] = useState(30)
  const [historyBusy, setHistoryBusy] = useState(false)
  const qualifyForce = Form.useWatch('force', qualifyForm)

  // 误报事件 / 紧急熔断
  const [incidents, setIncidents] = useState<RuleIncident[]>([])
  const [incidentStatus, setIncidentStatus] = useState('open')
  const [incidentLoading, setIncidentLoading] = useState(false)
  const [breakerOpen, setBreakerOpen] = useState(false)
  const [breakerForm] = Form.useForm()

  // 搜索、列筛选与批量选择
  const [minedQ, setMinedQ] = useState('')
  const [customQ, setCustomQ] = useState('')
  const [incidentQ, setIncidentQ] = useState('')
  const [breakerQ, setBreakerQ] = useState('')
  const [minedFilters, setMinedFilters] = useState<MinedFilters>({})
  const [customFilters, setCustomFilters] = useState<CustomFilters>({})
  const [incidentFilters, setIncidentFilters] = useState<IncidentFilters>({})
  const [breakerFilters, setBreakerFilters] = useState<BreakerFilters>({})
  const [selectedMined, setSelectedMined] = useState<string[]>([])
  const [selectedCustom, setSelectedCustom] = useState<string[]>([])
  const [selectedIncidents, setSelectedIncidents] = useState<number[]>([])
  const [selectedBreakers, setSelectedBreakers] = useState<string[]>([])
  const [minedPage, setMinedPage] = useState<TablePager>({ current: 1, pageSize: 50 })
  const [customPage, setCustomPage] = useState<TablePager>({ current: 1, pageSize: 50 })
  const [incidentPage, setIncidentPage] = useState<TablePager>({ current: 1, pageSize: 30 })
  const [evidencePage, setEvidencePage] = useState<TablePager>({ current: 1, pageSize: 20 })

  const load = useCallback(async () => {
    setLoading(true)
    setErr('')
    try {
      const [r, p] = await Promise.all([
        api<RulesPayload>('/api/rules'),
        api<any>('/api/policy'),
      ])
      setData(r)
      setPolicyRules((p?.policy?.rules || null) as PolicyRules | null)
    } catch (e: any) {
      setErr(e?.message || '加载失败')
    } finally {
      setLoading(false)
    }
  }, [])

  const loadIncidents = useCallback(async (status = incidentStatus) => {
    setIncidentLoading(true)
    try {
      const r = await api<any>(`/api/rules/incidents?status=${encodeURIComponent(status)}&limit=100`)
      setIncidents(r?.items || [])
    } catch (e: any) {
      message.error(e?.message || '事件加载失败')
    } finally {
      setIncidentLoading(false)
    }
  }, [incidentStatus])

  useEffect(() => {
    load()
    loadIncidents('open')
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [load])

  const minedData = useMemo(
    () => (data?.rules || []).filter((r) => matchesQuery(minedQ, r.id, r.name, r.regex)),
    [data?.rules, minedQ],
  )
  const customData = useMemo(
    () => (data?.custom || []).filter((r) =>
      matchesQuery(customQ, r.id, r.name, r.regex, sourceLabel(r.source), r.kind, r.state)),
    [data?.custom, customQ],
  )
  const incidentData = useMemo(
    () => incidents.filter((i) =>
      matchesQuery(incidentQ, i.id, i.rule, i.rule_name, i.reason, i.status,
        i.detail?.note,
        Array.isArray(i.detail?.samples) ? i.detail.samples.join(' ') : '')),
    [incidents, incidentQ],
  )
  const breakerData = useMemo(
    () => (data?.breakers || []).filter((b) =>
      matchesQuery(breakerQ, b.rule, b.reason, b.mode, b.actor, b.note)),
    [data?.breakers, breakerQ],
  )

  const minedBlockEligible = useMemo(
    () => minedData.filter((r) =>
      selectedMined.includes(r.id) && r.verdict === 'keep' && !r.breaker).length,
    [minedData, selectedMined],
  )
  const customBlockEligible = useMemo(
    () => customData.filter((r) =>
      selectedCustom.includes(r.id) && r.is_qualified && !r.breaker && r.can_block !== false).length,
    [customData, selectedCustom],
  )

  const clearMinedSelection = () => setSelectedMined([])
  const clearCustomSelection = () => setSelectedCustom([])
  const clearIncidentSelection = () => setSelectedIncidents([])
  const clearBreakerSelection = () => setSelectedBreakers([])

  const authInfo = data?.authoritative
  const diskSha = authInfo?.sha1_16 || ''
  const policySha = policyRules?.ruleset_sha1_16 || ''
  const cs = data?.custom_state

  /** 三种"看起来有规则、其实不生效"的状态，必须在页面上说清楚。 */
  const drift = useMemo(() => {
    if (!authInfo?.present) return null
    if (!policyRules) return null
    if (!policyRules.enabled) {
      return {
        type: 'warning' as const,
        msg: '规则集已生成，但策略里 `rules.enabled=false`（全局刹车/熔断）。采集器会记录命中证据，但不会因此告警或阻断。',
      }
    }
    if (diskSha && policySha && diskSha !== policySha) {
      return {
        type: 'error' as const,
        msg:
          `磁盘规则集指纹（${diskSha}）与策略记录的（${policySha}）不一致 —— ` +
          '采集器会把整条规则通道当作未启用（宁少拦、不多拦）。重新「提升」一次即可对齐。',
      }
    }
    return null
  }, [authInfo?.present, policyRules, diskSha, policySha])

  const pendingTesting = useMemo(
    () => (data?.custom || []).filter((r) => r.enabled && !r.is_qualified),
    [data?.custom],
  )

  /* ------------------------------------------------------------ 写操作 */

  const patchState = async (r: RuleRow, body: { enabled?: boolean; action?: string }) => {
    // 只有挖出的候选走 `/api/rules/{rule}`；其余（manual / crs / custom）都在
    // `rules_custom` 表里，必须走 `/api/rules/custom/{id}`。
    const isCustom = r.source !== 'mined'
    const url = isCustom
      ? `/api/rules/custom/${encodeURIComponent(r.id)}`
      : `/api/rules/${encodeURIComponent(r.id)}`
    setBusy(r.id)
    try {
      const out = await api<any>(url, { method: 'PATCH', body })
      const warns: string[] = out?.warnings || []
      message.success('已更新')
      if (warns.length) {
        Modal.warning({ title: '提醒', content: warns.join('\n'), width: 560 })
      }
      await load()
    } catch (e: any) {
      message.error(e?.message || '更新失败')
    } finally {
      setBusy('')
    }
  }

  const bulkEnableMined = (onlyUnproven: boolean) => {
    const unproven = (data?.rules || []).filter((r) => r.verdict !== 'keep')
    Modal.confirm({
      title: onlyUnproven ? '把「证据不足」的候选也调成合格？' : '把全部候选调成合格？',
      width: 560,
      content: (
        <div>
          <p>
            将把 <b>{onlyUnproven ? unproven.length : (data?.rules || []).length} 条</b>
            {onlyUnproven ? '证据不足的候选' : '候选（全量）'}标为「合格」。
          </p>
          <ul style={{ paddingLeft: 18, margin: '6px 0' }}>
            <li>挖出的候选没有「测试中」这一档：启用即视为合格；</li>
            <li>非 <Text code>keep</Text> 一律<b>锁死 alert</b>，不阻断、不占预算；</li>
            <li>融合阻断 FPR 不变，但真实流量上的<b>告警噪声会增加</b>。</li>
          </ul>
          <p className="muted" style={{ margin: 0 }}>
            启用只改控制面状态；要在数据面生效还得再点「提升到现役」。
          </p>
        </div>
      ),
      okText: '确认启用',
      onOk: async () => {
        setBusy('bulk')
        try {
          const out = await api<any>('/api/rules/bulk-enable', {
            method: 'POST',
            body: { enabled: true, only_unproven: onlyUnproven },
          })
          message.success(`已启用 ${out?.n_changed ?? 0} 条；记得「提升到现役」才会生效`)
          await load()
        } catch (e: any) {
          message.error(e?.message || '批量启用失败')
        } finally {
          setBusy('')
        }
      },
    })
  }

  const bulkEnableCustom = () => {
    const total = (data?.custom || []).filter((r) => !r.enabled).length
    Modal.confirm({
      title: '批量让自撰规则进入测试？',
      width: 600,
      content: (
        <div>
          <p>
            将对 <b>{total}</b> 条尚未启用的自撰/导入规则执行「启用」：
          </p>
          <ul style={{ paddingLeft: 18, margin: '6px 0' }}>
            <li>启用<b>只要求 ① Rust 正则编译</b>，不等 ②③；</li>
            <li>未合格的规则会被<b>强制 alert</b>，真实命中会真的产生告警；</li>
            <li>确认合格前<b>不允许 block</b>；命中证据进 <Text code>event_rules</Text>；</li>
            <li>要让它们真正参与判定，还要点「提升到现役」。</li>
          </ul>
          <p className="muted" style={{ margin: 0 }}>
            编译失败的规则会逐条列出来，其余照常启用。
          </p>
        </div>
      ),
      okText: '批量启用测试',
      onOk: async () => {
        setBusy('bulk-custom')
        try {
          const out = await api<any>('/api/rules/custom/bulk-enable', {
            method: 'POST',
            body: { enabled: true },
          })
          const bad = out?.errors || []
          message.success(`已启用 ${out?.n_changed ?? 0} 条${bad.length ? `；${bad.length} 条编译失败` : ''}`)
          if (bad.length) {
            Modal.warning({
              title: '这些规则没启用（① 编译失败）',
              width: 720,
              content: (
                <div className="pre-wrap">
                  {bad.map((x: any) => `${x.rule}: ${x.error}`).join('\n\n')}
                </div>
              ),
            })
          }
          await load()
        } catch (e: any) {
          message.error(e?.message || '批量启用失败')
        } finally {
          setBusy('')
        }
      },
    })
  }

  const validate = async (r: RuleRow) => {
    setBusy(r.id)
    try {
      const out = await api<any>(`/api/rules/custom/${encodeURIComponent(r.id)}/validate`, {
        method: 'POST',
      })
      if (out?.demoted) {
        Modal.error({
          title: '实测误报：已撤销合格',
          content: out?.note || '真实良性回放出现误报，已强制 alert。',
        })
      } else if (out?.passed) {
        message.success('①②③ 全过（防御型看 ①②）；可以点「确认合格」')
      } else {
        const why = out?.failed_at || 'unknown'
        const g = out?.gates?.[why] || {}
        message.warning(
          why === 'benign_replay'
            ? `真实良性回放有误报：${g?.benign_hits ?? '?'} 次`
            : why === 'attack_replay'
              ? '攻击回放 0 命中：池里没有这类样本，先启用去真实流量里攒证据'
              : `校验未过：${why}`,
        )
      }
      await load()
    } catch (e: any) {
      message.error(e?.message || '校验失败')
    } finally {
      setBusy('')
    }
  }

  const remove = (r: RuleRow) => {
    Modal.confirm({
      title: `删除规则 ${r.id}？`,
      content: '自撰规则一旦删除不可恢复。若它已在现役规则集里，请重新「提升」以把它移出现役。',
      okText: '删除',
      okButtonProps: { danger: true },
      onOk: async () => {
        try {
          await api(`/api/rules/custom/${encodeURIComponent(r.id)}`, { method: 'DELETE' })
          message.success('已删除')
          await load()
        } catch (e: any) {
          message.error(e?.message || '删除失败')
        }
      },
    })
  }

  const openCreate = () => {
    setEdit({ mode: 'create' })
    form.resetFields()
    form.setFieldsValue({
      name: '', regex: '', scopes: ['full'], severity: 'medium', weight: 1,
      action: 'alert', kind: 'detector', notes: '',
    })
  }

  const openEditModal = (r: RuleRow) => {
    setEdit({ mode: 'edit', rule: r })
    form.setFieldsValue({
      name: r.name, regex: r.regex, scopes: r.scopes?.length ? r.scopes : ['full'],
      severity: r.severity || 'medium', weight: r.weight ?? 1, action: r.action || 'alert',
      kind: r.kind || 'detector', notes: r.notes || '',
    })
  }

  const saveCustom = async () => {
    const v = await form.validateFields()
    // 内容编辑永远不会直接改动作；新规则/改过正则一律 alert，合格后在列表里逐条翻。
    v.action = 'alert'
    setBusy('form')
    try {
      if (edit?.mode === 'edit' && edit.rule) {
        await api(`/api/rules/custom/${encodeURIComponent(edit.rule.id)}`, {
          method: 'PUT',
          body: v,
        })
        message.success('已保存为草稿：内容一变，验证/合格自动作废，需要重新校验与确认。')
      } else {
        const out = await api<any>('/api/rules/custom', { method: 'POST', body: v })
        const w: string[] = out?.warnings || []
        message.success('已存为草稿（未启用、未合格）')
        if (w.length) Modal.warning({ title: '这条规则的提醒', content: w.join('\n'), width: 600 })
      }
      setEdit(null)
      await load()
    } catch (e: any) {
      if (e?.errorFields) return // 表单校验错误，antd 已经标红
      message.error(e?.message || '保存失败')
    } finally {
      setBusy('')
    }
  }

  const openPromote = () => {
    setPromoteOpen(true)
    setPreview(null)
    setPromoteRes(null)
    promoteForm.setFieldsValue({ min_weight_to_block: 1.0, rule_budget_cap: 0.003, note: '' })
  }

  const doPreview = async () => {
    const v = await promoteForm.validateFields()
    setBusy('preview')
    try {
      setPreview(await api<any>('/api/rules/preview-authoritative', { method: 'POST', body: v }))
      setPromoteRes(null)
    } catch (e: any) {
      message.error(e?.message || '预览失败')
    } finally {
      setBusy('')
    }
  }

  const doPromote = async () => {
    const v = await promoteForm.validateFields()
    setPromoting(true)
    try {
      const res = await api<any>('/api/rules/promote', { method: 'POST', body: v })
      setPromoteRes(res)
      message.success('已提升为现役规则集')
      await load()
    } catch (e: any) {
      message.error(e?.message || '提升失败（已自动回滚，策略与规则集均未改动）')
    } finally {
      setPromoting(false)
    }
  }

  /* ------------------------------------------------------------ 证据 / 合格 / 熔断 */

  const openEvidence = async (r: RuleRow) => {
    setEvidenceRid(r.id)
    setEvidenceOpen(true)
    setEvidence(null)
    setEvidenceLoading(true)
    try {
      setEvidence(await api<RuleEvidence>(`/api/rules/${encodeURIComponent(r.id)}/evidence?days=7&limit=50`))
    } catch (e: any) {
      message.error(e?.message || '证据加载失败')
    } finally {
      setEvidenceLoading(false)
    }
  }

  const reloadEvidence = async () => {
    if (!evidenceRid) return
    setEvidenceLoading(true)
    try {
      setEvidence(await api<RuleEvidence>(`/api/rules/${encodeURIComponent(evidenceRid)}/evidence?days=7&limit=50`))
    } catch (e: any) {
      message.error(e?.message || '证据加载失败')
    } finally {
      setEvidenceLoading(false)
    }
  }

  const sampleFeedback = async (s: RuleSample, verdict: string) => {
    try {
      await api('/api/feedback', {
        method: 'POST',
        body: { event_id: s.event_id, verdict, note: null },
      })
      message.success('已记录人工标签')
      await reloadEvidence()
      await load()
    } catch (e: any) {
      message.error(e?.message || '提交失败')
    }
  }

  const openQualify = (r: RuleRow) => {
    setQualify(r)
    qualifyForm.resetFields()
    qualifyForm.setFieldsValue({ note: r.qualification_note || '', force: false })
  }

  /** 用历史告警回放验证（只读 + 缓存证据；规则一改就失效）。 */
  const runHistory = async (rid: string) => {
    setHistoryBusy(true)
    try {
      const out = await api<any>(
        `/api/rules/custom/${encodeURIComponent(rid)}/history-evidence`,
        { method: 'POST', body: { days: historyDays } },
      )
      if (out.ok) message.success(`历史回放：${out.reason}`)
      else message.warning(`历史回放：${out.reason}`)
      const fresh = await api<RulesPayload>('/api/rules')
      setData(fresh)
      const r = (fresh.custom || []).find((x) => x.id === rid)
      if (r) {
        if (qualify && qualify.id === rid) setQualify(r)
        if (evidenceOpen) await reloadEvidence()
      }
    } catch (e: any) {
      message.error(e?.message || '历史回放失败')
    } finally {
      setHistoryBusy(false)
    }
  }

  const doQualify = async () => {
    if (!qualify) return
    const v = await qualifyForm.validateFields()
    setBusy(qualify.id)
    try {
      await api(`/api/rules/${encodeURIComponent(qualify.id)}/qualify`, {
        method: 'POST',
        body: { note: v.note || '', force: !!v.force, source: v.force ? 'admin_override' : 'manual' },
      })
      message.success('已确认合格；现在可以逐条翻 block')
      setQualify(null)
      await load()
      if (evidenceOpen) await reloadEvidence()
    } catch (e: any) {
      message.error(e?.message || '确认失败')
    } finally {
      setBusy('')
    }
  }

  const doUnqualify = (r: RuleRow) => {
    Modal.confirm({
      title: `撤销 ${r.id} 的合格？`,
      content: '撤销后 action 强制回 alert；要重新阻断需重新确认。这个动作不会自动重提升。',
      okText: '撤销',
      okButtonProps: { danger: true },
      onOk: async () => {
        try {
          await api(`/api/rules/${encodeURIComponent(r.id)}/unqualify`, {
            method: 'POST',
            body: { note: '控制台撤销合格' },
          })
          message.success('已撤销合格')
          await load()
          if (evidenceOpen) await reloadEvidence()
        } catch (e: any) {
          message.error(e?.message || '撤销失败')
        }
      },
    })
  }

  const monitor = data?.monitor || { auto_breaker: true, breaker_alerts: true }

  const saveMonitor = async (patch: any, okMsg: string) => {
    setBusy('monitor')
    try {
      await api<any>('/api/rules/monitor/settings', { method: 'PUT', body: patch })
      message.success(okMsg)
      await load()
    } catch (e: any) {
      message.error(e?.message || '保存失败')
    } finally {
      setBusy('')
    }
  }

  const toggleAutoBreaker = (next: boolean) => {
    if (next) {
      Modal.confirm({
        title: '开启自动熔断？',
        content: (
          <div>
            <p>只对<b>未验证</b>规则生效：测试中 / 强行启用的规则达到噪声阈值会被移出现役。</p>
            <p className="muted">已验证规则（合格 / proven）永不自动熔断，只告警。</p>
          </div>
        ),
        okText: '开启',
        onOk: () => saveMonitor({ auto_breaker: true }, '已开启自动熔断'),
      })
      return
    }
    let closeAlerts = false
    Modal.confirm({
      title: '关闭自动熔断？',
      width: 560,
      content: (
        <div>
          <p>关闭后监控<b>只发告警、绝不修改规则集</b>；手动熔断不受影响。</p>
          <p className="muted">已验证规则本来就不会被自动熔断。</p>
          <div style={{ marginTop: 8 }}>
            <Switch
              size="small"
              onChange={(v) => {
                closeAlerts = v
              }}
            />{' '}
            同时关闭<b>熔断类告警</b>（误报 / 噪声）
            <div className="muted" style={{ marginTop: 4 }}>
              不影响「命中量突增 / 阻断量突增」告警 —— 那是安全信号，永远保留。
            </div>
          </div>
        </div>
      ),
      okText: '关闭',
      onOk: () =>
        saveMonitor(
          closeAlerts ? { auto_breaker: false, breaker_alerts: false } : { auto_breaker: false },
          closeAlerts ? '已关闭自动熔断与熔断类告警' : '已关闭自动熔断（告警保留）',
        ),
    })
  }

  const toggleBreakerAlerts = (next: boolean) => {
    if (next) {
      saveMonitor({ breaker_alerts: true }, '已开启熔断类告警')
      return
    }
    Modal.confirm({
      title: '关闭熔断类告警？',
      content: (
        <div>
          <p>不再新建「人工确认误报」「告警噪声」事件。</p>
          <p className="muted">
            命中量 / 阻断量突增告警不受影响，永远保留；即将执行的自动静默仍会留事件。
          </p>
        </div>
      ),
      okText: '关闭',
      onOk: () => saveMonitor({ breaker_alerts: false }, '已关闭熔断类告警'),
    })
  }

  const applyBreaker = (scope: string, rule: string | null, reason = 'manual') => {
    const label = scope === 'channel' ? '关闭规则通道' : scope === 'all_block' ? '全部阻断规则降为 alert' : `熔断 ${rule}`
    const target = [...(data?.custom || []), ...(data?.rules || [])].find((x) => x.id === rule)
    const verified = !!(target && (target.is_qualified || target.qualified === 'proven'))
    Modal.confirm({
      title: `确认${label}？`,
      width: 560,
      content: (
        <div>
          <p>熔断只降动作、<b>不停采集</b>；5 秒内热重载，证据继续留档。</p>
          {verified ? (
            <p>
              <Tag color="green">已验证</Tag>
              该规则已验证，通常只应告警；手动熔断仍会按规则动作自动选择降级方式。
            </p>
          ) : null}
          <p className="muted">
            预算沿用旧值（更保守），后台重标定后恢复。恢复 = 删熔断行 + 还原产物。
          </p>
        </div>
      ),
      okText: '立即熔断',
      okButtonProps: { danger: true },
      onOk: async () => {
        setBusy('breaker')
        try {
          const out = await api<any>('/api/rules/breaker', {
            method: 'POST',
            body: { scope, rule, reason, note: '控制台手动熔断' },
          })
          message.success(`已执行：策略 v${out?.policy_version}，block ${out?.counts?.block ?? '?'} 条`)
          await load()
          await loadIncidents('open')
        } catch (e: any) {
          message.error(e?.message || '熔断失败')
        } finally {
          setBusy('')
        }
      },
    })
  }

  const restoreBreaker = (rule: string | null, all = false) => {
    Modal.confirm({
      title: all ? '恢复全部熔断？' : rule ? `恢复 ${rule}？` : '重新打开规则通道？',
      content: '会按熔断前快照还原产物并删除熔断行。如果刚恢复 block，建议先观察再提升。',
      okText: '恢复',
      onOk: async () => {
        setBusy('breaker')
        try {
          const out = await api<any>('/api/rules/breaker/restore', {
            method: 'POST',
            body: all
              ? { all: true, channel_on: true, note: '控制台恢复全部熔断' }
              : rule
                ? { rule, channel_on: false, note: '控制台恢复' }
                : { channel_on: true, note: '控制台重新打开规则通道' },
          })
          message.success(`已恢复；策略 v${out?.policy_version}`)
          await load()
          await loadIncidents('open')
        } catch (e: any) {
          message.error(e?.message || '恢复失败')
        } finally {
          setBusy('')
        }
      },
    })
  }

  const scanNow = async () => {
    setBusy('scan')
    try {
      const out = await api<any>('/api/rules/monitor/scan', { method: 'POST' })
      message.success(
        `扫描完成：新开 ${out?.opened?.length ?? 0} 个事件，自动熔断 ${out?.auto_broken?.length ?? 0} 条`,
      )
      await loadIncidents('open')
      await load()
    } catch (e: any) {
      message.error(e?.message || '扫描失败')
    } finally {
      setBusy('')
    }
  }

  const ackIncident = async (inc: RuleIncident) => {
    try {
      await api(`/api/rules/incidents/${inc.id}/ack`, { method: 'POST', body: { note: '已阅' } })
      message.success('已标记已阅（不等于关闭）')
      await loadIncidents(incidentStatus)
    } catch (e: any) {
      message.error(e?.message || '操作失败')
    }
  }

  const resolveIncident = (inc: RuleIncident, restore: boolean) => {
    Modal.confirm({
      title: `关闭事件 #${inc.id}？`,
      content: restore
        ? '会同时尝试恢复对应的熔断（规则或通道），然后标记解决。'
        : '只标记解决，不恢复熔断。若规则仍处于熔断状态，需要另外点「恢复」。',
      okText: restore ? '解决并恢复' : '仅解决',
      onOk: async () => {
        try {
          const out = await api<any>(`/api/rules/incidents/${inc.id}/resolve`, {
            method: 'POST',
            body: { note: '控制台处理', restore },
          })
          message.success(out?.restored ? '已关闭并恢复' : '已关闭')
          await loadIncidents(incidentStatus)
          await load()
        } catch (e: any) {
          message.error(e?.message || '操作失败')
        }
      },
    })
  }

  const showBulkOutcome = (title: string, out: any) => {
    const errors = out?.errors || []
    const skipped = out?.skipped || []
    const n = out?.n_changed ?? out?.changed?.length ?? 0
    if (!errors.length && !skipped.length) {
      message.success(`${title}：成功 ${n} 条`)
      return
    }
    Modal.info({
      title: `${title}结果`,
      width: 680,
      content: (
        <div>
          <p>成功 <b>{n}</b> 条；跳过/未处理 <b>{skipped.length}</b> 条；失败 <b>{errors.length}</b> 条。</p>
          {errors.length ? (
            <div style={{ maxHeight: 260, overflow: 'auto' }}>
              <b>失败原因</b>
              <ul style={{ paddingLeft: 18, margin: '6px 0' }}>
                {errors.map((e: any, idx: number) => (
                  <li key={`${e.rule ?? e.id ?? idx}-${idx}`}>
                    <Text code>{String(e.rule ?? e.id ?? '?')}</Text>：{e.error || '未知错误'}
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
          {skipped.length ? (
            <p className="muted">跳过：{skipped.map((x: any) => String(x)).join('、')}</p>
          ) : null}
        </div>
      ),
    })
  }

  const bulkRules = (scope: 'mined' | 'custom', op: string, action?: string) => {
    const ids = scope === 'mined' ? selectedMined : selectedCustom
    if (!ids.length) return
    const labels: Record<string, string> = {
      enable: '批量启用',
      disable: '批量停用',
      set_action: action === 'block' ? '批量设为 block' : '批量设为 alert',
      delete: '批量删除',
    }
    const label = labels[op] || op
    const danger = op === 'delete' || (op === 'set_action' && action === 'block')
    Modal.confirm({
      title: `${label}（${ids.length} 条）`,
      width: 640,
      content: (
        <div>
          <p>范围：<b>{scope === 'mined' ? '挖出的候选' : '自撰规则'}</b>，共 {ids.length} 条。</p>
          {op === 'set_action' && action === 'block' ? (
            <p className="muted">
              没有证据或未人工确认合格的规则会被跳过，不会绕过合格/熔断限制。
              {scope === 'mined' ? `当前选中规则中可 block：${minedBlockEligible} 条。`
                : `当前选中规则中可 block：${customBlockEligible} 条。`}
            </p>
          ) : null}
          {op === 'delete' ? <p><b>删除不可撤销。</b></p> : null}
          <p className="muted">改动只写入控制面，需重新「提升到现役」才会在数据面生效。</p>
        </div>
      ),
      okText: label,
      okButtonProps: { danger },
      onOk: async () => {
        setBusy('bulk-selected')
        try {
          const out = await api<any>('/api/rules/bulk', {
            method: 'POST',
            body: { scope, ids, op, action },
          })
          showBulkOutcome(label, out)
          const changed = new Set<string>((out?.changed || []).map(String))
          if (scope === 'mined') {
            setSelectedMined((prev) => prev.filter((id) => !changed.has(id)))
          } else {
            setSelectedCustom((prev) => prev.filter((id) => !changed.has(id)))
          }
          await load()
        } catch (e: any) {
          message.error(e?.message || `${label}失败`)
        } finally {
          setBusy('')
        }
      },
    })
  }

  const bulkIncidents = (op: 'ack' | 'resolve', restore = false) => {
    if (!selectedIncidents.length) return
    const label = op === 'ack' ? '批量已阅' : restore ? '批量解决并恢复' : '批量解决'
    Modal.confirm({
      title: `${label}（${selectedIncidents.length} 条）`,
      content: restore
        ? '关闭所选事件，并尝试按各自熔断前快照恢复对应规则/规则通道。'
        : op === 'ack'
          ? '只把未处理事件标记为已阅，不等于关闭。'
          : '只标记解决，不恢复熔断；需要恢复的请用「解决并恢复」。',
      okText: label,
      okButtonProps: { danger: restore },
      onOk: async () => {
        setBusy('incident-bulk')
        try {
          const out = await api<any>('/api/rules/incidents/bulk', {
            method: 'POST',
            body: {
              ids: selectedIncidents,
              op,
              restore,
              note: restore ? '控制台批量解决并恢复' : '控制台批量处理',
            },
          })
          showBulkOutcome(label, out)
          const changed = new Set<number>((out?.changed || []).map(Number))
          setSelectedIncidents((prev) => prev.filter((id) => !changed.has(id)))
          await loadIncidents(incidentStatus)
          await load()
        } catch (e: any) {
          message.error(e?.message || `${label}失败`)
        } finally {
          setBusy('')
        }
      },
    })
  }

  const bulkRestoreBreakers = () => {
    if (!selectedBreakers.length) return
    Modal.confirm({
      title: `批量恢复熔断（${selectedBreakers.length} 条）`,
      content: '按每条规则熔断前的快照恢复；用户已停用的规则不会被悄悄放回现役。',
      okText: '批量恢复',
      onOk: async () => {
        setBusy('breaker-bulk')
        try {
          const out = await api<any>('/api/rules/breaker/bulk-restore', {
            method: 'POST',
            body: { rules: selectedBreakers, note: '控制台批量恢复熔断' },
          })
          showBulkOutcome('批量恢复熔断', out)
          const changed = new Set<string>((out?.restored || []).map(String))
          setSelectedBreakers((prev) => prev.filter((id) => !changed.has(id)))
          await load()
        } catch (e: any) {
          message.error(e?.message || '批量恢复失败')
        } finally {
          setBusy('')
        }
      },
    })
  }

  /* ------------------------------------------------------------ 表列 */

  const actionSelect = (r: RuleRow, disabled: boolean) => {
    const locked = r.action_locked || disabled || (!r.can_block && r.source !== 'mined')
    return (
      <Tooltip
        title={
          r.breaker
            ? '该规则已被熔断：先恢复，再确认是否值得阻断'
            : locked
              ? r.source === 'mined'
                ? '这条没有攻击证据（verdict != keep），只能 alert'
                : '未人工确认合格，只能 alert；先点「确认合格」'
              : 'alert 只告警；block 计入阻断预算'
        }
      >
        <Select
          size="small"
          style={{ width: 92 }}
          value={r.action || 'alert'}
          disabled={!isAdmin || locked || busy === r.id}
          onChange={(v) => patchState(r, { action: v })}
          options={[
            { value: 'alert', label: <Tag color="gold">alert</Tag> },
            { value: 'block', label: <Tag color="red">block</Tag> },
          ]}
        />
      </Tooltip>
    )
  }

  const onlineCell = (r: RuleRow) => {
    const o = r.online
    if (!o) return <span className="muted">-</span>
    return (
      <Tooltip
        title={
          `窗口 7 天：命中 ${fmtInt(o.hits)} 条事件\n` +
          `确认攻击 ${fmtInt(o.confirmed_attack)}｜确认正常 ${fmtInt(o.confirmed_benign)}\n` +
          `疑似攻击 ${fmtInt(o.suspected_attack)}（模型也报了，只提示）｜未标注 ${fmtInt(o.unlabeled)}\n` +
          `最近 ${fmtTs(o.last_ts)}`
        }
      >
        <Space size={4} wrap>
          <Tag>{fmtInt(o.hits)}</Tag>
          <Tag color={o.confirmed_attack ? 'red' : 'default'}>攻 {fmtInt(o.confirmed_attack)}</Tag>
          <Tag color={o.confirmed_benign ? 'green' : 'default'}>良 {fmtInt(o.confirmed_benign)}</Tag>
          {o.suspected_attack ? <Tag color="gold">疑 {fmtInt(o.suspected_attack)}</Tag> : null}
        </Space>
      </Tooltip>
    )
  }

  const minedColumns = [
    { title: '规则', dataIndex: 'id', key: 'id', width: 210, render: (v: string) => <Text code>{v}</Text> },
    {
      title: '实测证据',
      dataIndex: 'verdict',
      key: 'verdict',
      width: 176,
      filters: Object.keys(VERDICT_COLOR).map((v) => ({ text: v, value: v })),
      filteredValue: minedFilters.verdict,
      onFilter: (value, r) => String(r.verdict ?? '') === String(value),
      render: (v: string) => (
        <Tooltip title={verdictHint({ verdict: v } as RuleRow)}>
          <Tag color={VERDICT_COLOR[v] || 'default'}>{v}</Tag>
        </Tooltip>
      ),
    },
    {
      title: '合格方式',
      key: 'grade',
      width: 124,
      filters: [
        { text: '有证据', value: 'proven' },
        { text: '用户放行', value: 'override' },
        { text: '未启用', value: 'disabled' },
      ],
      filteredValue: minedFilters.grade,
      onFilter: (value, r) => minedGrade(r) === String(value),
      render: (_: any, r: RuleRow) => {
        if (r.verdict === 'keep') return <Tag color="green">有证据</Tag>
        const on = !!r.enabled
        return (
          <Tooltip
            title={
              on
                ? '用户强行启用：证据不足，只告警、不阻断'
                : '证据不足或实测误报；仍可启用，但只能 alert'
            }
          >
            <Tag color={on ? 'volcano' : 'default'}>{on ? '用户放行' : '未启用'}</Tag>
          </Tooltip>
        )
      },
    },
    {
      title: '良性命中',
      width: 118,
      render: (_: any, r: RuleRow) => (
        <Tooltip title={`${fmtInt(r.benign_hits)} / ${fmtInt(r.benign_n)}`}>
          <span>
            {fmtInt(r.benign_hits)} <span className="muted">({fmtPct(r.benign_rate, 4)})</span>
          </span>
        </Tooltip>
      ),
    },
    {
      title: '攻击命中',
      width: 118,
      render: (_: any, r: RuleRow) => (
        <Tooltip title={`${fmtInt(r.attack_hits)} / ${fmtInt(r.attack_n)}`}>
          <span>
            {fmtInt(r.attack_hits)} <span className="muted">({fmtPct(r.attack_rate, 3)})</span>
          </span>
        </Tooltip>
      ),
    },
    {
      title: '在线命中（7天）',
      width: 210,
      render: (_: any, r: RuleRow) => onlineCell(r),
    },
    {
      title: '动作',
      key: 'action',
      width: 104,
      filters: ACTION_FILTERS,
      filteredValue: minedFilters.action,
      onFilter: (value, r) => actionKey(r) === String(value),
      render: (_: any, r: RuleRow) => (
        <Space size={2}>
          {r.breaker ? <Tag color="red">熔断</Tag> : null}
          {actionSelect(r, false)}
        </Space>
      ),
    },
    {
      title: '启用（合格）',
      key: 'enabled',
      width: 116,
      filters: ENABLED_FILTERS,
      filteredValue: minedFilters.enabled,
      onFilter: (value, r) => (r.enabled ? 'enabled' : 'disabled') === String(value),
      render: (_: any, r: RuleRow) => (
        <Tooltip
          title={
            r.verdict === 'keep'
              ? '有攻击证据：启用后可 alert，也可翻 block'
              : '证据不足也能启用，但只能 alert（不会阻断流量）'
          }
        >
          <Switch
            size="small"
            checked={!!r.enabled}
            disabled={!isAdmin || busy === r.id}
            onChange={(v) => patchState(r, { enabled: v })}
          />
        </Tooltip>
      ),
    },
    {
      title: '操作',
      width: 100,
      render: (_: any, r: RuleRow) => (
        <Button size="small" icon={<EyeOutlined />} onClick={() => openEvidence(r)}>
          证据
        </Button>
      ),
    },
    { title: '正则', dataIndex: 'regex', ellipsis: true },
  ]

  const customColumns = [
    {
      title: '规则 / 名称',
      key: 'kind',
      width: 240,
      filters: [
        { text: 'detector', value: 'detector' },
        { text: 'guard', value: 'guard' },
      ],
      filteredValue: customFilters.kind,
      onFilter: (value, r) => String(r.kind || 'detector') === String(value),
      render: (_: any, r: RuleRow) => (
        <div>
          <Text code>{r.id}</Text>
          {r.kind === 'guard' ? <Tag color="purple" style={{ marginLeft: 4 }}>guard</Tag> : null}
          <div className="muted">{r.name}</div>
        </div>
      ),
    },
    {
      title: '状态',
      key: 'state',
      width: 150,
      filters: CUSTOM_STATE_FILTERS,
      filteredValue: customFilters.state,
      onFilter: (value, r) => customStateKey(r) === String(value),
      render: (_: any, r: RuleRow) => (
        <Space size={2} wrap>
          {stateTag(r)}
          <Tag color={r.enabled ? 'blue' : 'default'}>{r.enabled ? '已启用' : '未启用'}</Tag>
        </Space>
      ),
    },
    {
      title: '在线证据（7天）',
      width: 210,
      render: (_: any, r: RuleRow) => (
        <Space size={4} wrap>
          {onlineCell(r)}
          <Button size="small" type="link" icon={<EyeOutlined />} onClick={() => openEvidence(r)}>
            看样本
          </Button>
        </Space>
      ),
    },
    {
      title: '合格',
      key: 'qualified',
      width: 150,
      filters: [
        { text: '已确认', value: 'qualified' },
        { text: '待确认', value: 'suggest' },
        { text: '证据不足', value: 'insufficient' },
      ],
      filteredValue: customFilters.qualified,
      onFilter: (value, r) => customQualifiedKey(r) === String(value),
      render: (_: any, r: RuleRow) => {
        if (r.is_qualified) {
          return (
            <Space size={2} wrap>
              <Tooltip
                title={
                  `确认人 ${r.qualified_by || '-'}｜来源 ${r.qualification_source || '-'}\n` +
                  `${r.qualification_note || ''}\n${fmtTs(r.qualified_at)}`
                }
              >
                <Tag color="green" icon={<CheckCircleOutlined />}>已确认</Tag>
              </Tooltip>
              <Button size="small" type="link" icon={<UndoOutlined />} disabled={!isAdmin}
                      onClick={() => doUnqualify(r)} />
            </Space>
          )
        }
        if (r.suggest_qualified) {
          return (
            <Button size="small" type="primary" ghost disabled={!isAdmin} onClick={() => openQualify(r)}>
              确认合格
            </Button>
          )
        }
        return (
          <Tooltip title={(r.blockers || []).join('；') || '证据不足'}>
            <Tag>证据不足</Tag>
          </Tooltip>
        )
      },
    },
    {
      title: '动作',
      key: 'action',
      width: 110,
      filters: ACTION_FILTERS,
      filteredValue: customFilters.action,
      onFilter: (value, r) => actionKey(r) === String(value),
      render: (_: any, r: RuleRow) => (
        <Space size={2}>
          {r.breaker ? <Tag color="red" icon={<FireOutlined />}>熔断</Tag> : null}
          {actionSelect(r, false)}
        </Space>
      ),
    },
    {
      title: '启用',
      key: 'enabled',
      width: 70,
      filters: ENABLED_FILTERS,
      filteredValue: customFilters.enabled,
      onFilter: (value, r) => (r.enabled ? 'enabled' : 'disabled') === String(value),
      render: (_: any, r: RuleRow) => (
        <Tooltip
          title={
            '启用 = 参与判定（只告警），只要求 ① 编译；合格要人工确认。' +
            (r.compiled ? '' : ' 打开时会先跑编译。')
          }
        >
          <Switch
            size="small"
            checked={!!r.enabled}
            disabled={!isAdmin || busy === r.id}
            onChange={(v) => patchState(r, { enabled: v })}
          />
        </Tooltip>
      ),
    },
    {
      title: '三关',
      key: 'gate',
      width: 170,
      filters: [
        { text: '全通过', value: 'passed' },
        { text: '有失败', value: 'failed' },
        { text: '未校验', value: 'unchecked' },
      ],
      filteredValue: customFilters.gate,
      onFilter: (value, r) => gateKey(r) === String(value),
      render: (_: any, r: RuleRow) => {
        const g = gateOf(r)
        const dot = (ok?: boolean | null, label?: string) => (
          <Tag color={ok === true ? 'green' : ok === false ? 'red' : 'default'}>
            {label} {ok === true ? '✓' : ok === false ? '✗' : '?'}
          </Tag>
        )
        return (
          <Tooltip
            title={
              `正则：${g.reg?.passed ? '通过' : g.reg?.error || g.reg?.stderr || '未过'}\n` +
              `良性：${g.benign?.benign_hits ?? g.benign?.hits ?? '?'}/${g.benign?.benign_n ?? g.benign?.n ?? '?'}\n` +
              `攻击：${g.attack?.not_applicable ? '不适用（guard）' : `${g.attack?.attack_hits ?? g.attack?.hits ?? '?'}/${g.attack?.attack_n ?? g.attack?.n ?? '?'}`}` +
              (g.failedAt ? `\n卡在：${g.failedAt}` : '')
            }
          >
            <Space size={2} wrap>
              {dot(g.reg?.passed, '正则')}
              {dot(g.benign?.passed, '良性')}
              {g.attack?.not_applicable ? <Tag>攻击 不适用</Tag> : dot(g.attack?.passed, '攻击')}
            </Space>
          </Tooltip>
        )
      },
    },
    {
      title: '来源',
      dataIndex: 'source',
      key: 'source',
      width: 90,
      filters: ['manual', 'custom', 'crs', 'wafjson'].map((v) => ({
        text: sourceLabel(v), value: v,
      })),
      filteredValue: customFilters.source,
      onFilter: (value, r) => String(r.source || '') === String(value),
      render: (v: string) => {
        const color = v === 'wafjson' ? 'blue' : v === 'crs' ? 'purple' : 'default'
        return <Tag color={color}>{sourceLabel(v)}</Tag>
      },
    },
    {
      title: '操作',
      width: 180,
      render: (_: any, r: RuleRow) => {
        const menu = {
          items: [
            r.is_qualified
              ? { key: 'breaker', label: '熔断该规则', danger: true, disabled: !isAdmin }
              : { key: 'breaker', label: '熔断 / 移出现役', danger: true, disabled: !isAdmin },
            { key: 'evidence', label: '查看在线证据' },
            { key: 'history', label: '用历史告警验证', disabled: !canWrite },
            {
              key: 'qualify',
              // 不再要求「已有证据」才可点：证据不足时也要能打开弹窗去跑历史回放/强制确认。
              label: r.suggest_qualified ? '确认合格' : '确认合格（证据不足）',
              disabled: !isAdmin,
            },
          ],
          onClick: ({ key }: any) => {
            if (key === 'breaker') applyBreaker('rule', r.id, 'manual')
            if (key === 'evidence') openEvidence(r)
            if (key === 'history') openEvidence(r)
            if (key === 'qualify') openQualify(r)
          },
        }
        return (
          <Space size={4}>
            <Button
              size="small"
              icon={<SafetyCertificateOutlined />}
              loading={busy === r.id}
              disabled={!isAdmin}
              onClick={() => validate(r)}
            >
              校验
            </Button>
            <Button size="small" icon={<EditOutlined />} disabled={!isAdmin} onClick={() => openEditModal(r)} />
            <Button size="small" danger icon={<DeleteOutlined />} disabled={!isAdmin} onClick={() => remove(r)} />
            <Dropdown menu={menu} trigger={['click']}>
              <Button size="small">…</Button>
            </Dropdown>
          </Space>
        )
      },
    },
    { title: '正则', dataIndex: 'regex', ellipsis: true },
  ]

  const incidentColumns = [
    {
      title: '严重度',
      dataIndex: 'severity',
      key: 'severity',
      width: 84,
      filters: [
        { text: 'high', value: 'high' },
        { text: 'medium', value: 'medium' },
        { text: 'low', value: 'low' },
      ],
      filteredValue: incidentFilters.severity,
      onFilter: (value, r) => String(r.severity || '') === String(value),
      render: (v: string) => <Tag color={SEVERITY_COLOR[v] || 'default'}>{v}</Tag>,
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      width: 86,
      filters: [
        { text: '未处理', value: 'open' },
        { text: '已阅', value: 'acked' },
        { text: '已关闭', value: 'resolved' },
      ],
      filteredValue: incidentFilters.status,
      onFilter: (value, r) => String(r.status || '') === String(value),
      render: (v: string) => (
        <Tag color={v === 'open' ? 'red' : v === 'acked' ? 'gold' : 'green'}>
          {v === 'open' ? '未处理' : v === 'acked' ? '已阅' : '已关闭'}
        </Tag>
      ),
    },
    {
      title: '规则',
      width: 220,
      render: (_: any, r: RuleIncident) =>
        r.rule ? (
          <div>
            <Text code>{r.rule}</Text>
            <div className="muted">{r.rule_name || ''}</div>
            <Space size={2} wrap style={{ marginTop: 2 }}>
              {r.detail?.verified ? (
                <Tooltip title="已验证规则：只告警，不自动熔断">
                  <Tag color="green">已验证 · 只告警</Tag>
                </Tooltip>
              ) : null}
              {r.detail?.auto_action === 'disable' ? (
                <Tooltip title="未验证规则噪声达标，已自动移出现役；证据与审计保留">
                  <Tag color="volcano">已自动静默</Tag>
                </Tooltip>
              ) : null}
            </Space>
          </div>
        ) : (
          <Tag color="volcano">全局 / 规则通道</Tag>
        ),
    },
    {
      title: '原因',
      dataIndex: 'reason',
      key: 'reason',
      width: 120,
      filters: Object.keys(REASON_LABEL).map((v) => ({ text: REASON_LABEL[v], value: v })),
      filteredValue: incidentFilters.reason,
      onFilter: (value, r) => String(r.reason || '') === String(value),
      render: (v: string) => <Tag color={v === 'confirmed_fp' ? 'red' : 'gold'}>{REASON_LABEL[v] || v}</Tag>,
    },
    {
      title: '窗口证据',
      render: (_: any, r: RuleIncident) => {
        const d = r.detail || {}
        return (
          <span className="muted">
            {d.window_min ? `${d.window_min} 分钟｜` : ''}
            命中 {fmtInt(d.hits ?? d.blocks)}｜确认攻击 {fmtInt(d.confirmed_attack)}｜确认正常{' '}
            {fmtInt(d.confirmed_benign)}｜疑似 {fmtInt(d.suspected_attack)}
            {d.samples?.length ? `｜样本 #${d.samples.join(', #')}` : ''}
            {d.note ? `｜${d.note}` : ''}
          </span>
        )
      },
    },
    { title: '时间', dataIndex: 'opened_at', width: 165, render: (v) => fmtTs(v) },
    {
      title: '操作',
      width: 260,
      render: (_: any, r: RuleIncident) => (
        <Space size={4} wrap>
          {r.status === 'open' ? (
            <Button size="small" onClick={() => ackIncident(r)} disabled={!canWrite}>已阅</Button>
          ) : null}
          {r.status !== 'resolved' ? (
            <>
              <Button
                size="small"
                danger
                icon={<FireOutlined />}
                disabled={!isAdmin}
                loading={busy === 'breaker'}
                onClick={() =>
                  r.scope === 'channel'
                    ? applyBreaker('channel', null, r.reason)
                    : applyBreaker('rule', r.rule || null, r.reason)
                }
              >
                {r.scope === 'channel' ? '关闭通道' : '熔断'}
              </Button>
              {(r.rule
                ? (data?.breakers || []).some((b) => b.rule === r.rule)
                : !!policyRules && !policyRules.enabled) ? (
                <Button
                  size="small"
                  icon={<UndoOutlined />}
                  disabled={!isAdmin}
                  onClick={() => restoreBreaker(r.rule || null)}
                >
                  恢复
                </Button>
              ) : null}
              <Button size="small" onClick={() => resolveIncident(r, false)} disabled={!canWrite}>
                解决
              </Button>
            </>
          ) : null}
        </Space>
      ),
    },
  ]

  const breakerColumns = [
    {
      title: '规则',
      dataIndex: 'rule',
      width: 230,
      render: (v: string) => <Text code>{v}</Text>,
    },
    {
      title: '熔断方式',
      dataIndex: 'mode',
      key: 'mode',
      width: 120,
      filters: [
        { text: 'block → alert', value: 'alert' },
        { text: '移出现役', value: 'disable' },
      ],
      filteredValue: breakerFilters.mode,
      onFilter: (value, r) => String(r.mode || 'alert') === String(value),
      render: (v: string) => (
        <Tag color={v === 'disable' ? 'volcano' : 'red'}>
          {v === 'disable' ? '移出现役' : 'block → alert'}
        </Tag>
      ),
    },
    {
      title: '原因',
      dataIndex: 'reason',
      key: 'reason',
      width: 120,
      filters: Object.keys(REASON_LABEL).map((v) => ({ text: REASON_LABEL[v], value: v })),
      filteredValue: breakerFilters.reason,
      onFilter: (value, r) => String(r.reason || '') === String(value),
      render: (v: string) => <Tag color="gold">{REASON_LABEL[v] || v}</Tag>,
    },
    { title: '操作者', dataIndex: 'actor', width: 110 },
    { title: '时间', dataIndex: 'opened_at', width: 165, render: (v: number) => fmtTs(v) },
    {
      title: '备注',
      dataIndex: 'note',
      render: (v: string) => <span className="muted">{v || '-'}</span>,
    },
    {
      title: '操作',
      width: 90,
      render: (_: any, r: RuleBreaker) => (
        <Button
          size="small"
          icon={<UndoOutlined />}
          disabled={!isAdmin}
          onClick={() => restoreBreaker(r.rule)}
        >
          恢复
        </Button>
      ),
    },
  ]

  /* ------------------------------------------------------------ 渲染 */

  const openIncidentCount = incidents.filter((i) => i.status === 'open').length

  return (
    <div>
      <div className="toolbar">
        <Title level={4} className="page-title">
          规则管理
        </Title>
        <Space wrap>
          <Button icon={<ReloadOutlined />} onClick={load} loading={loading}>
            刷新
          </Button>
          <Button
            icon={<SafetyCertificateOutlined />}
            disabled={!isAdmin}
            loading={busy === 'bulk'}
            onClick={() => bulkEnableMined(true)}
          >
            挖出候选全部启用
          </Button>
          <Button
            icon={<ExperimentOutlined />}
            disabled={!isAdmin}
            loading={busy === 'bulk-custom'}
            onClick={bulkEnableCustom}
          >
            全部启用测试
          </Button>
          <Button
            danger
            icon={<FireOutlined />}
            disabled={!isAdmin}
            onClick={() => {
              breakerForm.resetFields()
              breakerForm.setFieldsValue({ scope: 'all_block', rule: '', reason: 'manual', note: '' })
              setBreakerOpen(true)
            }}
          >
            紧急熔断
          </Button>
          <Button
            type="primary"
            icon={<ThunderboltOutlined />}
            disabled={!isAdmin}
            onClick={openPromote}
          >
            提升到现役
          </Button>
        </Space>
      </div>

      {err ? <Alert type="error" message={err} showIcon style={{ marginBottom: 12 }} /> : null}
      {drift ? (
        <Alert type={drift.type} showIcon message={drift.msg} style={{ marginBottom: 12 }} />
      ) : null}
      {pendingTesting.length > 0 && authInfo?.present ? (
        <Alert
          type="info"
          showIcon
          style={{ marginBottom: 12 }}
          message={`有 ${pendingTesting.length} 条规则处于「测试中」：它们已经启用，但只有点「提升到现役」后才会真正参与判定并产生 alert。`}
          action={
            <Button size="small" type="primary" ghost onClick={openPromote}>
              去提升
            </Button>
          }
        />
      ) : null}

      <Card size="small" style={{ marginBottom: 12 }}>
        <Descriptions
          size="small"
          column={{ xs: 1, sm: 1, md: 2, lg: 2, xl: 3 }}
          items={[
            {
              key: 'present',
              label: '现役规则集',
              children: authInfo?.present ? (
                <Tag color="green">{authInfo.ruleset_id || '已生成'}</Tag>
              ) : (
                <Tag>无</Tag>
              ),
            },
            {
              key: 'sha',
              label: '指纹 sha1_16',
              children: diskSha ? <Text code>{diskSha}</Text> : '-',
            },
            {
              key: 'counts',
              label: '条数 / block',
              children: authInfo?.counts ? (
                <span>
                  {fmtInt(authInfo.counts.total)}
                  <span className="muted"> / {fmtInt(authInfo.counts.block)}</span>
                  {authInfo.counts.testing ? (
                    <span className="muted">（测试 {fmtInt(authInfo.counts.testing)}）</span>
                  ) : null}
                  {authInfo.counts.breaker ? (
                    <Tag color="red" style={{ marginLeft: 6 }}>熔断 {fmtInt(authInfo.counts.breaker)}</Tag>
                  ) : null}
                </span>
              ) : (
                '-'
              ),
            },
            {
              key: 'custom',
              label: '自撰规则（启用/合格）',
              children: cs ? (
                <Tooltip
                  title={
                    `已启用 ${fmtInt(cs.n_enabled)}；已人工确认 ${fmtInt(cs.n_qualified)}；` +
                    `测试中 ${fmtInt(cs.n_testing)}；已编译未启用 ${fmtInt(cs.n_ready)}；` +
                    `建议合格 ${fmtInt(cs.n_suggest)}；` +
                    `良性有误报 ${fmtInt(cs.n_noisy)}；未编译 ${fmtInt(cs.n_uncompiled)}`
                  }
                >
                  <span>
                    {fmtInt(cs.n_enabled)} / {fmtInt(cs.n_total)}
                    <span className="muted">
                      {' '}（合格 {fmtInt(cs.n_qualified)}，测试 {fmtInt(cs.n_testing)}）
                    </span>
                  </span>
                </Tooltip>
              ) : (
                '-'
              ),
            },
            {
              key: 'mined_enabled',
              label: '挖出候选（启用）',
              children: data?.enabled ? (
                <Tooltip
                  title={
                    `有攻击证据 ${fmtInt(data.enabled.n_proven)} 条；` +
                    `用户强行放行 ${fmtInt(data.enabled.n_user_override)} 条（只告警）`
                  }
                >
                  <span>
                    {fmtInt(data.enabled.n_enabled)} / {fmtInt(data.enabled.n_total)}
                  </span>
                </Tooltip>
              ) : (
                '-'
              ),
            },
            {
              key: 'gen',
              label: '生成时间',
              children: fmtTs(authInfo?.generated_at),
            },
            {
              key: 'policy',
              label: '策略里的规则通道',
              children: policyRules ? (
                policyRules.enabled ? (
                  <Tag color="green">
                    启用 · {fmtInt(policyRules.n_rules)} 条 / block {fmtInt(policyRules.n_block_rules)}
                  </Tag>
                ) : (
                  <Tag color="orange">未启用（全局刹车/熔断）</Tag>
                )
              ) : (
                <Tag>策略无 rules 块（双通道）</Tag>
              ),
            },
            {
              key: 'thr',
              label: '阻断线',
              children: policyRules?.min_weight_to_block ?? authInfo?.min_weight_to_block ?? '-',
            },
            {
              key: 'budget',
              label: '预算扣减',
              children:
                policyRules?.budget_deducted !== undefined ? (
                  <Tooltip
                    title={
                      `监督目标 ${fmtPct(policyRules?.nominal_target_fpr, 3)} → ` +
                      `实际 ${fmtPct(policyRules?.sup_target_fpr, 3)}（融合阻断 FPR 维持不变）`
                    }
                  >
                    <span>{fmtPct(policyRules?.budget_deducted, 4)}</span>
                  </Tooltip>
                ) : (
                  '-'
                ),
            },
            {
              key: 'decode',
              label: '解码阶段',
              children: (
                <Space size={2} wrap>
                  {(authInfo?.decode || data?.decode || []).map((d) => (
                    <Tag key={d}>{d}</Tag>
                  ))}
                </Space>
              ),
            },
          ]}
        />
      </Card>

      <Tabs
        activeKey={tab}
        onChange={(key) => {
          setTab(key)
          clearMinedSelection()
          clearCustomSelection()
          clearIncidentSelection()
          clearBreakerSelection()
        }}
        items={[
          {
            key: 'mined',
            label: `挖出的候选（${data?.rules?.length ?? 0}）`,
            children: (
              <>
                <Alert
                  type="info"
                  showIcon
                  style={{ marginBottom: 12 }}
                  message={
                    <span>
                      候选来自 <Text code>artifacts/rule_candidates.json</Text>，匹配一律在
                      <b>解码后</b>文本上评估。
                    </span>
                  }
                  description={
                    data?.eval ? (
                      <span className="muted">
                        良性 n={fmtInt(data.eval.benign_n)}（{data.eval.benign_sources}）｜攻击 n=
                        {fmtInt(data.eval.attack_n)}（{data.eval.attack_sources}）｜解码：{data.eval.decoding}
                      </span>
                    ) : null
                  }
                />
                <Space wrap style={{ marginBottom: 8 }}>
                  <Input
                    allowClear
                    prefix={<SearchOutlined />}
                    placeholder="搜索规则 ID / 名称 / 正则"
                    style={{ width: 320 }}
                    value={minedQ}
                    onChange={(e) => {
                      setMinedQ(e.target.value)
                      setMinedPage((p) => ({ ...p, current: 1 }))
                      clearMinedSelection()
                    }}
                  />
                  <Button
                    size="small"
                    onClick={() => {
                      setMinedQ('')
                      setMinedFilters({})
                      setMinedPage((p) => ({ ...p, current: 1 }))
                      clearMinedSelection()
                    }}
                  >
                    清除筛选
                  </Button>
                  <span className="muted">
                    搜索命中 {minedData.length} 条，共 {data?.rules?.length ?? 0} 条
                  </span>
                </Space>
                {selectedMined.length > 0 && isAdmin ? (
                  <Space wrap style={{ marginBottom: 8 }}>
                    <Text strong>已选 {selectedMined.length} 条</Text>
                    <Button size="small" type="primary" loading={busy === 'bulk-selected'}
                            onClick={() => bulkRules('mined', 'enable')}>批量启用</Button>
                    <Button size="small" loading={busy === 'bulk-selected'}
                            onClick={() => bulkRules('mined', 'disable')}>批量停用</Button>
                    <Button size="small" loading={busy === 'bulk-selected'}
                            onClick={() => bulkRules('mined', 'set_action', 'alert')}>设为 alert</Button>
                    <Button size="small" danger disabled={!minedBlockEligible} loading={busy === 'bulk-selected'}
                            onClick={() => bulkRules('mined', 'set_action', 'block')}>设为 block</Button>
                    <Button size="small" type="link" onClick={clearMinedSelection}>清除选择</Button>
                  </Space>
                ) : null}
                <Table
                  size="small"
                  rowKey="id"
                  loading={loading || busy === 'bulk-selected'}
                  dataSource={minedData}
                  rowSelection={isAdmin ? {
                    selectedRowKeys: selectedMined,
                    onChange: (keys) => setSelectedMined(keys.map(String)),
                  } : undefined}
                  onChange={(pagination, filters, _sorter, extra) => {
                    setMinedFilters({
                      verdict: picked(filters, 'verdict'),
                      grade: picked(filters, 'grade'),
                      action: picked(filters, 'action'),
                      enabled: picked(filters, 'enabled'),
                    })
                    setMinedPage({
                      pageSize: pagination.pageSize || 50,
                      current: extra.action === 'filter' ? 1 : (pagination.current || 1),
                    })
                    if (extra.action === 'filter') clearMinedSelection()
                  }}
                  pagination={{
                    ...minedPage,
                    showSizeChanger: true,
                    pageSizeOptions: RULE_PAGE_SIZE_OPTIONS,
                    showTotal: (n) => `共 ${n} 条`,
                  }}
                  columns={minedColumns}
                  scroll={{ x: 1400 }}
                />
                <div className="muted" style={{ marginTop: 8 }}>
                  绿色 = 有攻击证据（可 alert / block）；红色 = 真实良性上有实测误报；金色 = 评估池无法验证；
                  橙色 = 攻击侧命中太少。后三类也<b>可以</b>启用，但一律锁死 <Text code>alert</Text>
                  —— 没有攻击证据就不允许阻断流量。挖出的候选没有「测试中」档：启用即视为合格。
                </div>
              </>
            ),
          },
          {
            key: 'custom',
            label: `自撰规则（${data?.custom?.length ?? 0}）`,
            children: (
              <>
                <Alert
                  type="warning"
                  showIcon
                  style={{ marginBottom: 12 }}
                  message="新模型：启用 ≠ 合格。启用只要求 ① Rust 正则编译（只告警）；合格要人工确认；只有合格才能 block。"
                  description={
                    <span className="muted">
                      合格判据：<b>detector</b> = ①编译 + ②真实良性 0 误报 + ③攻击回放 &gt; 0，
                      或真实流量里 ≥1 条<b>人工确认攻击</b>且确认良性为 0；
                      <b>guard</b> = ①编译 + ②真实良性 0 误报 + 管理员填写政策理由（不看 ③）。
                      模型也报了的只算「疑似」，不单独定罪。回放用数据面同一份 Rust 实现。
                    </span>
                  }
                />
                <Space wrap style={{ marginBottom: 8 }}>
                  <Input
                    allowClear
                    prefix={<SearchOutlined />}
                    placeholder="搜索规则 ID / 名称 / 正则 / 来源"
                    style={{ width: 340 }}
                    value={customQ}
                    onChange={(e) => {
                      setCustomQ(e.target.value)
                      setCustomPage((p) => ({ ...p, current: 1 }))
                      clearCustomSelection()
                    }}
                  />
                  <Button
                    size="small"
                    onClick={() => {
                      setCustomQ('')
                      setCustomFilters({})
                      setCustomPage((p) => ({ ...p, current: 1 }))
                      clearCustomSelection()
                    }}
                  >
                    清除筛选
                  </Button>
                  <span className="muted">
                    搜索命中 {customData.length} 条，共 {data?.custom?.length ?? 0} 条
                  </span>
                </Space>
                <div style={{ marginBottom: 8 }}>
                  <Space wrap>
                    <Button type="dashed" icon={<PlusOutlined />} disabled={!isAdmin} onClick={openCreate}>
                      新建规则
                    </Button>
                    <Button icon={<ExperimentOutlined />} disabled={!isAdmin} loading={busy === 'bulk-custom'}
                            onClick={bulkEnableCustom}>
                      全部启用测试
                    </Button>
                    <Button icon={<ReloadOutlined />} onClick={() => load()} loading={loading}>
                      刷新证据
                    </Button>
                  </Space>
                </div>
                {selectedCustom.length > 0 && isAdmin ? (
                  <Space wrap style={{ marginBottom: 8 }}>
                    <Text strong>已选 {selectedCustom.length} 条</Text>
                    <Button size="small" type="primary" loading={busy === 'bulk-selected'}
                            onClick={() => bulkRules('custom', 'enable')}>批量启用</Button>
                    <Button size="small" loading={busy === 'bulk-selected'}
                            onClick={() => bulkRules('custom', 'disable')}>批量停用</Button>
                    <Button size="small" loading={busy === 'bulk-selected'}
                            onClick={() => bulkRules('custom', 'set_action', 'alert')}>设为 alert</Button>
                    <Button size="small" danger disabled={!customBlockEligible} loading={busy === 'bulk-selected'}
                            onClick={() => bulkRules('custom', 'set_action', 'block')}>设为 block</Button>
                    <Button size="small" danger loading={busy === 'bulk-selected'}
                            onClick={() => bulkRules('custom', 'delete')}>批量删除</Button>
                    <Button size="small" type="link" onClick={clearCustomSelection}>清除选择</Button>
                  </Space>
                ) : null}
                <Table
                  size="small"
                  rowKey="id"
                  loading={loading || busy === 'bulk-selected'}
                  dataSource={customData}
                  rowSelection={isAdmin ? {
                    selectedRowKeys: selectedCustom,
                    onChange: (keys) => setSelectedCustom(keys.map(String)),
                  } : undefined}
                  onChange={(pagination, filters, _sorter, extra) => {
                    setCustomFilters({
                      state: picked(filters, 'state'),
                      qualified: picked(filters, 'qualified'),
                      action: picked(filters, 'action'),
                      enabled: picked(filters, 'enabled'),
                      source: picked(filters, 'source'),
                      kind: picked(filters, 'kind'),
                      gate: picked(filters, 'gate'),
                    })
                    setCustomPage({
                      pageSize: pagination.pageSize || 50,
                      current: extra.action === 'filter' ? 1 : (pagination.current || 1),
                    })
                    if (extra.action === 'filter') clearCustomSelection()
                  }}
                  pagination={{
                    ...customPage,
                    showSizeChanger: true,
                    pageSizeOptions: RULE_PAGE_SIZE_OPTIONS,
                    showTotal: (n) => `共 ${n} 条`,
                  }}
                  columns={customColumns}
                  scroll={{ x: 1500 }}
                />
                <div className="muted" style={{ marginTop: 8 }}>
                  匹配文本 = <Text code>{'{method} {path}?{query} {body}'}</Text>（再按 scope 单独评判）；
                  串尾请写 <Text code>\z</Text>，<Text code>$</Text> 在两侧语义不同（只会警告）。
                  测试中的命中会真的产生 alert（事件页有「测试」标记），方便用真实流量判断。
                </div>
              </>
            ),
          },
          {
            key: 'incidents',
            label: (
              <span>
                误报 / 熔断
                {openIncidentCount ? <Badge count={openIncidentCount} size="small" style={{ marginLeft: 6 }} /> : null}
              </span>
            ),
            children: (
              <>
                <Alert
                  type="warning"
                  showIcon
                  style={{ marginBottom: 12 }}
                  message="已验证规则永不自动熔断：命中再多、确认误报再多，也只告警，降级由人决定。"
                  description={
                    <span className="muted">
                      自动熔断只作用于未验证规则（测试中 / 强行启用）：噪声达标会被移出现役。
                      已验证规则（合格 / proven）只会生成「人工确认误报」「命中量突增」等告警。
                      命中量 / 阻断量突增告警不受任何开关影响 —— 真攻击也会涨量，按量自动熔断
                      等于给攻击者一个关规则的后门。
                    </span>
                  }
                />
                <Space style={{ marginBottom: 8 }} wrap>
                  <Input
                    allowClear
                    prefix={<SearchOutlined />}
                    placeholder="搜索事件 / 规则 / 原因"
                    style={{ width: 260 }}
                    value={incidentQ}
                    onChange={(e) => {
                      setIncidentQ(e.target.value)
                      setIncidentPage((p) => ({ ...p, current: 1 }))
                      clearIncidentSelection()
                    }}
                  />
                  <Select
                    size="small"
                    value={incidentStatus}
                    style={{ width: 130 }}
                    onChange={(v) => {
                      setIncidentStatus(v)
                      setIncidentFilters({})
                      setIncidentPage((p) => ({ ...p, current: 1 }))
                      clearIncidentSelection()
                      loadIncidents(v)
                    }}
                    options={[
                      { value: 'open', label: '未处理' },
                      { value: 'acked', label: '已阅' },
                      { value: 'resolved', label: '已关闭' },
                    ]}
                  />
                  <Button
                    size="small"
                    onClick={() => {
                      setIncidentQ('')
                      setIncidentFilters({})
                      setBreakerQ('')
                      setBreakerFilters({})
                      setIncidentPage((p) => ({ ...p, current: 1 }))
                      clearIncidentSelection()
                      clearBreakerSelection()
                    }}
                  >
                    清除筛选
                  </Button>
                  <span className="muted">当前状态筛选下搜索命中 {incidentData.length} 条</span>
                  <Button size="small" icon={<ReloadOutlined />} onClick={() => loadIncidents(incidentStatus)}
                          loading={incidentLoading}>
                    刷新
                  </Button>
                  <Button size="small" disabled={!isAdmin} loading={busy === 'scan'} onClick={scanNow}>
                    立即扫一轮
                  </Button>
                  <Tooltip title="只对未验证规则自动动作；已验证规则永不自动熔断">
                    <Space size={4}>
                      <Switch
                        size="small"
                        checked={!!monitor.auto_breaker}
                        disabled={!isAdmin}
                        loading={busy === 'monitor'}
                        onChange={toggleAutoBreaker}
                      />
                      <span className="muted">自动熔断</span>
                    </Space>
                  </Tooltip>
                  <Tooltip title="只影响「人工确认误报 / 告警噪声」；命中量/阻断量突增告警永远保留">
                    <Space size={4}>
                      <Switch
                        size="small"
                        checked={!!monitor.breaker_alerts}
                        disabled={!isAdmin}
                        loading={busy === 'monitor'}
                        onChange={toggleBreakerAlerts}
                      />
                      <span className="muted">熔断类告警</span>
                    </Space>
                  </Tooltip>
                  <Button size="small" danger disabled={!isAdmin} onClick={() => applyBreaker('all_block', null, 'manual')}>
                    全部阻断降为 alert
                  </Button>
                  <Button size="small" disabled={!isAdmin} onClick={() => restoreBreaker(null)}>
                    重新打开规则通道
                  </Button>
                  <Button
                    size="small"
                    disabled={!isAdmin || !(data?.breakers || []).length}
                    onClick={() => restoreBreaker(null, true)}
                  >
                    恢复全部熔断
                  </Button>
                </Space>
                {selectedIncidents.length > 0 && canWrite ? (
                  <Space wrap style={{ marginBottom: 8 }}>
                    <Text strong>已选 {selectedIncidents.length} 个事件</Text>
                    <Button size="small" loading={busy === 'incident-bulk'}
                            onClick={() => bulkIncidents('ack')}>批量已阅</Button>
                    <Button size="small" loading={busy === 'incident-bulk'}
                            onClick={() => bulkIncidents('resolve')}>批量解决</Button>
                    <Button size="small" danger disabled={!isAdmin} loading={busy === 'incident-bulk'}
                            onClick={() => bulkIncidents('resolve', true)}>解决并恢复</Button>
                    <Button size="small" type="link" onClick={clearIncidentSelection}>清除选择</Button>
                  </Space>
                ) : null}
                {selectedBreakers.length > 0 && isAdmin ? (
                  <Space wrap style={{ marginBottom: 8 }}>
                    <Text strong>已选 {selectedBreakers.length} 条熔断</Text>
                    <Button size="small" loading={busy === 'breaker-bulk'}
                            onClick={bulkRestoreBreakers}>批量恢复</Button>
                    <Button size="small" type="link" onClick={clearBreakerSelection}>清除选择</Button>
                  </Space>
                ) : null}
                <div className="muted" style={{ marginBottom: 6 }}>
                  当前熔断覆盖（{ (data?.breakers || []).length} 条）：
                  {policyRules && !policyRules.enabled ? ' 规则通道已关闭。' : ' 规则通道开启。'}
                </div>
                <Space wrap style={{ marginBottom: 6 }}>
                  <Input
                    allowClear
                    prefix={<SearchOutlined />}
                    placeholder="搜索熔断规则 / 原因"
                    style={{ width: 260 }}
                    value={breakerQ}
                    onChange={(e) => {
                      setBreakerQ(e.target.value)
                      clearBreakerSelection()
                    }}
                  />
                  <span className="muted">搜索命中 {breakerData.length} 条，共 {(data?.breakers || []).length} 条</span>
                </Space>
                <Table
                  size="small"
                  rowKey="rule"
                  dataSource={breakerData}
                  rowSelection={isAdmin ? {
                    selectedRowKeys: selectedBreakers,
                    onChange: (keys) => setSelectedBreakers(keys.map(String)),
                  } : undefined}
                  onChange={(_pagination, filters) => {
                    setBreakerFilters({
                      mode: picked(filters, 'mode'),
                      reason: picked(filters, 'reason'),
                    })
                    clearBreakerSelection()
                  }}
                  columns={breakerColumns}
                  pagination={false}
                  scroll={{ x: 1000 }}
                  style={{ marginBottom: 16 }}
                />
                <Table
                  size="small"
                  rowKey="id"
                  loading={incidentLoading || busy === 'incident-bulk'}
                  dataSource={incidentData}
                  rowSelection={canWrite ? {
                    selectedRowKeys: selectedIncidents,
                    onChange: (keys) => setSelectedIncidents(keys.map(Number)),
                  } : undefined}
                  onChange={(pagination, filters, _sorter, extra) => {
                    setIncidentFilters({
                      severity: picked(filters, 'severity'),
                      status: picked(filters, 'status'),
                      reason: picked(filters, 'reason'),
                    })
                    setIncidentPage({
                      pageSize: pagination.pageSize || 30,
                      current: extra.action === 'filter' ? 1 : (pagination.current || 1),
                    })
                    if (extra.action === 'filter') clearIncidentSelection()
                  }}
                  pagination={{
                    ...incidentPage,
                    showSizeChanger: true,
                    pageSizeOptions: INCIDENT_PAGE_SIZE_OPTIONS,
                    showTotal: (n) => `共 ${n} 条`,
                  }}
                  columns={incidentColumns}
                  scroll={{ x: 1300 }}
                />
              </>
            ),
          },
        ]}
      />

      {/* ---------------------------------------------------- 自撰规则弹窗 */}
      <Modal
        open={!!edit}
        title={edit?.mode === 'edit' ? `编辑规则 ${edit.rule?.id}` : '新建自撰规则'}
        okText="保存为草稿"
        confirmLoading={busy === 'form'}
        onCancel={() => setEdit(null)}
        onOk={saveCustom}
        width={760}
        destroyOnClose
      >
        <Alert
          type="info"
          showIcon
          style={{ marginBottom: 12 }}
          message={
            <span>
              保存后是<b>草稿</b>：未启用、未合格、不能 block。启用只要求 ① 编译；合格要人工确认。
              改任何内容都会让之前的验证/合格作废。
            </span>
          }
        />
        <Form form={form} layout="vertical" size="small">
          <Form.Item name="name" label="名称" rules={[{ required: true, message: '给规则起个能看懂的名字' }]}>
            <Input placeholder="例如：DVWA 命令注入 ping" maxLength={64} />
          </Form.Item>
          <Form.Item
            name="regex"
            label="正则（Rust regex 语法，线性时间）"
            rules={[{ required: true, message: '正则不能为空' }]}
          >
            <Input.TextArea rows={3} className="mono" placeholder="例如：\b(?:uname|id)\s+-a\b" />
          </Form.Item>
          <Space size={12} wrap>
            <Form.Item name="kind" label="类型" style={{ minWidth: 200 }}>
              <Select
                style={{ width: 190 }}
                options={[
                  { value: 'detector', label: 'detector（攻击检测型）' },
                  { value: 'guard', label: 'guard（防御型入口）' },
                ]}
              />
            </Form.Item>
            <Form.Item name="scopes" label="作用范围（可多选）" style={{ minWidth: 260 }}>
              <Select
                mode="multiple"
                style={{ minWidth: 240 }}
                options={(data?.scopes || ['full']).map((s) => ({ value: s, label: s }))}
              />
            </Form.Item>
            <Form.Item name="severity" label="严重度">
              <Select
                style={{ width: 120 }}
                options={(data?.severities || ['low', 'medium', 'high', 'critical']).map((s) => ({ value: s, label: s }))}
              />
            </Form.Item>
            <Form.Item name="weight" label="权重（计入阻断线）">
              <InputNumber min={0} max={10} step={0.1} style={{ width: 120 }} />
            </Form.Item>
          </Space>
          <Alert
            type="info"
            showIcon
            style={{ margin: '4px 0 12px' }}
            message="类型怎么选"
            description={
              <span className="muted">
                <b>detector</b>：对应一次真实攻击（SQLi/XSS/RCE…），合格需要攻击证据。
                <b>guard</b>：拒绝不该被访问的入口（.git / 管理入口 / actuator…），
                合格看「真实良性 0 误报 + 政策理由」，不要求攻击回放。
              </span>
            }
          />
          <Form.Item name="notes" label="备注（为什么加这条）">
            <Input.TextArea rows={2} maxLength={500} />
          </Form.Item>
        </Form>
      </Modal>

      {/* ---------------------------------------------------- 合格确认 */}
      <Modal
        open={!!qualify}
        title={`确认规则合格：${qualify?.id || ''}`}
        okText="确认合格"
        okButtonProps={{
          // 证据不够时必须显式勾「强制确认」，避免点了才报错。
          disabled: !!qualify && !qualify.suggest_qualified && !qualifyForce,
        }}
        confirmLoading={busy === qualify?.id}
        onCancel={() => setQualify(null)}
        onOk={doQualify}
        width={680}
      >
        {qualify ? (
          <>
            <Descriptions size="small" bordered column={2} style={{ marginBottom: 12 }}>
              <Descriptions.Item label="类型">{qualify.kind || 'detector'}</Descriptions.Item>
              <Descriptions.Item label="当前状态">{STATE_LABEL[qualify.state || ''] || qualify.state}</Descriptions.Item>
              <Descriptions.Item label="池内良性命中">
                {fmtInt(qualify.validation?.gates?.benign_replay?.benign_hits)}{' '}
                <span className="muted">
                  / {fmtInt(qualify.validation?.gates?.benign_replay?.benign_n)}
                </span>
              </Descriptions.Item>
              <Descriptions.Item label="池内攻击命中">
                {qualify.kind === 'guard' ? (
                  <Tag>不适用（guard）</Tag>
                ) : (
                  <span>
                    {fmtInt(qualify.validation?.gates?.attack_replay?.attack_hits)}{' '}
                    <span className="muted">/ {fmtInt(qualify.validation?.gates?.attack_replay?.attack_n)}</span>
                  </span>
                )}
              </Descriptions.Item>
              <Descriptions.Item label="在线确认攻击">
                <Tag color={qualify.online?.confirmed_attack ? 'red' : 'default'}>
                  {fmtInt(qualify.online?.confirmed_attack)}
                </Tag>
              </Descriptions.Item>
              <Descriptions.Item label="在线确认正常">
                <Tag color={qualify.online?.confirmed_benign ? 'green' : 'default'}>
                  {fmtInt(qualify.online?.confirmed_benign)}
                </Tag>
              </Descriptions.Item>
            </Descriptions>

            <Card
              size="small"
              title="历史告警回放（可选证据；只认人工标签，规则一改即失效）"
              style={{ marginBottom: 12 }}
            >
              <Space wrap style={{ marginBottom: 8 }}>
                <Select
                  size="small"
                  value={historyDays}
                  onChange={setHistoryDays}
                  disabled={historyBusy}
                  options={[
                    { value: 7, label: '最近 7 天' },
                    { value: 30, label: '最近 30 天' },
                    { value: 90, label: '最近 90 天' },
                  ]}
                />
                <Button
                  size="small"
                  loading={historyBusy}
                  disabled={!isAdmin}
                  onClick={() => runHistory(qualify.id)}
                >
                  用历史告警验证
                </Button>
                {qualify.history ? (
                  <Tag color={qualify.history_ok ? 'green' : qualify.history.ok ? 'orange' : 'gold'}>
                    {qualify.history_ok
                      ? '可合格（确认攻击 ≥1 / 确认良性 0）'
                      : qualify.history.ok
                        ? '历史证据够，但 ② 真实良性校验未过'
                        : '历史证据不足'}
                  </Tag>
                ) : (
                  <span className="muted">尚未回放</span>
                )}
              </Space>
              {qualify.history ? (
                <Descriptions size="small" bordered column={4}>
                  <Descriptions.Item label="扫描">
                    {fmtInt(qualify.history.scanned)}
                    {qualify.history.truncated ? '（已截断）' : ''}
                  </Descriptions.Item>
                  <Descriptions.Item label="命中">{fmtInt(qualify.history.matched)}</Descriptions.Item>
                  <Descriptions.Item label="确认攻击">
                    <Tag color={qualify.history.confirmed_attack ? 'red' : 'default'}>
                      {fmtInt(qualify.history.confirmed_attack)}
                    </Tag>
                  </Descriptions.Item>
                  <Descriptions.Item label="确认良性">
                    <Tag color={qualify.history.confirmed_benign ? 'green' : 'default'}>
                      {fmtInt(qualify.history.confirmed_benign)}
                    </Tag>
                  </Descriptions.Item>
                  <Descriptions.Item label="未标注">{fmtInt(qualify.history.unlabeled)}</Descriptions.Item>
                  <Descriptions.Item label="窗口">{qualify.history.days} 天</Descriptions.Item>
                  <Descriptions.Item label="回放时间" span={2}>
                    {qualify.history.created_at ? fmtTs(qualify.history.created_at) : '-'}
                  </Descriptions.Item>
                </Descriptions>
              ) : null}
              {qualify.history?.confirmed_benign ? (
                <Alert
                  type="warning"
                  showIcon
                  style={{ marginTop: 8 }}
                  message={`历史命中里有 ${fmtInt(qualify.history.confirmed_benign)} 条确认良性：不能用于合格，先修正则或排除该业务场景。`}
                />
              ) : null}
              {qualify.history?.ok && !qualify.history_ok ? (
                <Alert
                  type="info"
                  showIcon
                  style={{ marginTop: 8 }}
                  message="历史告警证据已够；还需先通过 ② 真实良性零误报（规则行「校验」）才能确认合格。"
                />
              ) : null}
            </Card>

            {qualify.kind === 'guard' ? (
              <Alert
                type="info"
                showIcon
                style={{ marginBottom: 12 }}
                message="防御型规则（guard）的合格判据 = ① 编译 + ② 真实良性 0 误报 + 政策理由；不看 ③ 攻击回放。"
              />
            ) : !qualify.suggest_qualified ? (
              <Alert
                type="warning"
                showIcon
                style={{ marginBottom: 12 }}
                message="证据还不够：池内 ③ 无样本、真实流量没有「人工确认攻击」、也没有可用的历史告警证据。"
                description="可以继续测试等样本，或点上面的「用历史告警验证」用已确认的历史事件佐证；如果坚持确认，勾选下面的「强制确认」并写清理由（会记 admin_override）。"
              />
            ) : null}
            <Form form={qualifyForm} layout="vertical" size="small">
              <Form.Item
                name="note"
                label={qualify.kind === 'guard' ? '政策理由（必填）' : '备注'}
                rules={qualify.kind === 'guard' ? [{ required: true, message: '防御型规则必须写政策理由' }] : []}
              >
                <Input.TextArea
                  rows={3}
                  maxLength={500}
                  placeholder={
                    qualify.kind === 'guard'
                      ? '例如：源站不允许访问 .git / 管理入口；任何访问都视为违规探测，直接拒绝。'
                      : '例如：真实流量里 3 条样本人工确认是 SQL 注入，无误报。'
                  }
                />
              </Form.Item>
              {!qualify.suggest_qualified ? (
                <Form.Item name="force" valuePropName="checked">
                  <Switch /> <span style={{ marginLeft: 8 }}>强制确认（证据不足，记 admin_override）</span>
                </Form.Item>
              ) : null}
            </Form>
            <div className="muted">
              确认后只代表「允许逐条翻 block」；要真正拦截还要把 action 改成 block 并「提升到现役」。
            </div>
          </>
        ) : null}
      </Modal>

      {/* ---------------------------------------------------- 证据抽屉 */}
      <Drawer
        width={1040}
        open={evidenceOpen}
        onClose={() => setEvidenceOpen(false)}
        title={evidence ? `规则证据：${evidence.rule}` : '规则证据'}
        extra={
          <Space>
            <Button size="small" icon={<ReloadOutlined />} loading={evidenceLoading} onClick={reloadEvidence}>
              刷新
            </Button>
            {evidence && evidence.source !== 'mined' ? (
              <Button
                size="small"
                type="primary"
                disabled={!isAdmin}
                onClick={() => {
                  const r = (data?.custom || []).find((x) => x.id === evidence.rule)
                  if (r) openQualify({ ...r, ...evidence.view })
                }}
              >
                确认合格
              </Button>
            ) : null}
          </Space>
        }
      >
        {evidence ? (
          <div>
            <Space style={{ marginBottom: 12 }} wrap>
              <Tag color={evidence.kind === 'guard' ? 'purple' : 'blue'}>{evidence.kind}</Tag>
              <Tag color={STATE_COLOR[evidence.state] || 'default'}>
                {STATE_LABEL[evidence.state] || evidence.state}
              </Tag>
              {evidence.source === 'mined' ? (
                <Tag color={evidence.state === 'keep' ? 'green' : 'gold'}>
                  {evidence.state === 'keep' ? '有攻击证据（可 block）' : '证据不足（只 alert）'}
                </Tag>
              ) : evidence.view?.is_qualified ? (
                <Tag color="green">已合格</Tag>
              ) : (
                <Tag>未合格</Tag>
              )}
              {evidence.view?.breaker ? <Tag color="red" icon={<FireOutlined />}>已熔断</Tag> : null}
              {evidence.qualified_at ? (
                <span className="muted">确认人 {evidence.qualified_by}｜{fmtTs(evidence.qualified_at)}</span>
              ) : null}
            </Space>

            {evidence.view?.blockers?.length ? (
              <Alert
                type="warning"
                showIcon
                style={{ marginBottom: 12 }}
                message="还差什么才能合格"
                description={
                  <ul style={{ margin: 0, paddingLeft: 18 }}>
                    {evidence.view.blockers.map((b: string) => <li key={b}>{b}</li>)}
                  </ul>
                }
              />
            ) : null}

            <Card size="small" title="① 离线三关（同一份 Rust 实现回放）">
              <Descriptions size="small" bordered column={3}>
                <Descriptions.Item label="正则编译">
                  {evidence.source === 'mined' ? (
                    <Tag>候选自带</Tag>
                  ) : evidence.offline?.regex_safety?.passed ? (
                    <Tag color="green">通过</Tag>
                  ) : (
                    <Tag color="red">未过</Tag>
                  )}
                </Descriptions.Item>
                <Descriptions.Item label="真实良性">
                  <Tag color={evidence.offline?.benign_replay?.passed ? 'green' : 'red'}>
                    {fmtInt(evidence.offline?.benign_replay?.benign_hits)} /{' '}
                    {fmtInt(evidence.offline?.benign_replay?.benign_n)}
                  </Tag>
                </Descriptions.Item>
                <Descriptions.Item label="攻击回放">
                  {evidence.offline?.attack_replay?.not_applicable ? (
                    <Tag>不适用（guard）</Tag>
                  ) : (
                    <Tag color={evidence.offline?.attack_replay?.passed ? 'green' : 'red'}>
                      {fmtInt(evidence.offline?.attack_replay?.attack_hits)} /{' '}
                      {fmtInt(evidence.offline?.attack_replay?.attack_n)}
                    </Tag>
                  )}
                </Descriptions.Item>
              </Descriptions>
              {evidence.kind === 'guard' ? (
                <div className="muted" style={{ marginTop: 8 }}>
                  防御型规则本来就不对应一次真实攻击：只要真实良性 0 误报，加上管理员的政策理由，就可以合格。
                </div>
              ) : null}
            </Card>

            <Card size="small" title="② 在线证据（7 天；只认人工标签）" style={{ marginTop: 12 }}>
              <Descriptions size="small" bordered column={5}>
                <Descriptions.Item label="命中事件">{fmtInt(evidence.online.hits)}</Descriptions.Item>
                <Descriptions.Item label="确认攻击">
                  <Tag color={evidence.online.confirmed_attack ? 'red' : 'default'}>
                    {fmtInt(evidence.online.confirmed_attack)}
                  </Tag>
                </Descriptions.Item>
                <Descriptions.Item label="确认正常">
                  <Tag color={evidence.online.confirmed_benign ? 'green' : 'default'}>
                    {fmtInt(evidence.online.confirmed_benign)}
                  </Tag>
                </Descriptions.Item>
                <Descriptions.Item label="疑似攻击">
                  <Tooltip title="模型也报了，但没有人工标签；只提示、不单独定罪">
                    <Tag color="gold">{fmtInt(evidence.online.suspected_attack)}</Tag>
                  </Tooltip>
                </Descriptions.Item>
                <Descriptions.Item label="未标注">{fmtInt(evidence.online.unlabeled)}</Descriptions.Item>
              </Descriptions>
              <div className="muted" style={{ marginTop: 8 }}>
                「模型说良性」不当作良性证据：规则和监督是并列通道，模型漏掉的正是规则该抓的。
                要给样本定性，在下面点「确认攻击 / 正常业务 / 待查」。
              </div>
            </Card>

            {evidence.source === 'custom' ? (
              <Card
                size="small"
                title="③ 历史告警回放（手动触发；只认人工标签，规则一改即失效）"
                style={{ marginTop: 12 }}
              >
                <Space wrap style={{ marginBottom: 8 }}>
                  <Select
                    size="small"
                    value={historyDays}
                    onChange={setHistoryDays}
                    disabled={historyBusy}
                    options={[
                      { value: 7, label: '最近 7 天' },
                      { value: 30, label: '最近 30 天' },
                      { value: 90, label: '最近 90 天' },
                    ]}
                  />
                  <Button
                    size="small"
                    loading={historyBusy}
                    disabled={!isAdmin}
                    onClick={() => runHistory(evidence.rule)}
                  >
                    用历史告警验证
                  </Button>
                  {evidence.history ? (
                    <Tag color={evidence.history_ok ? 'green' : evidence.history.ok ? 'orange' : 'gold'}>
                      {evidence.history_ok
                        ? '可合格（确认攻击 ≥1 / 确认良性 0）'
                        : evidence.history.ok
                          ? '历史证据够，但 ② 真实良性校验未过'
                          : '历史证据不足'}
                    </Tag>
                  ) : (
                    <span className="muted">尚未回放</span>
                  )}
                </Space>
                {evidence.history ? (
                  <Descriptions size="small" bordered column={4}>
                    <Descriptions.Item label="扫描">
                      {fmtInt(evidence.history.scanned)}
                      {evidence.history.truncated ? '（已截断）' : ''}
                    </Descriptions.Item>
                    <Descriptions.Item label="命中">{fmtInt(evidence.history.matched)}</Descriptions.Item>
                    <Descriptions.Item label="确认攻击">
                      <Tag color={evidence.history.confirmed_attack ? 'red' : 'default'}>
                        {fmtInt(evidence.history.confirmed_attack)}
                      </Tag>
                    </Descriptions.Item>
                    <Descriptions.Item label="确认良性">
                      <Tag color={evidence.history.confirmed_benign ? 'green' : 'default'}>
                        {fmtInt(evidence.history.confirmed_benign)}
                      </Tag>
                    </Descriptions.Item>
                    <Descriptions.Item label="未标注">{fmtInt(evidence.history.unlabeled)}</Descriptions.Item>
                    <Descriptions.Item label="窗口">{evidence.history.days} 天</Descriptions.Item>
                    <Descriptions.Item label="回放时间" span={2}>
                      {evidence.history.created_at ? fmtTs(evidence.history.created_at) : '-'}
                    </Descriptions.Item>
                  </Descriptions>
                ) : null}
              </Card>
            ) : null}

            <Card
              size="small"
              title="④ 命中样本（点一行可打开事件；反馈写独立台账）"
              style={{ marginTop: 12 }}
            >
              <Table
                size="small"
                rowKey={(r: RuleSample) => `${r.event_id}|${r.field || ''}`}
                loading={evidenceLoading}
                dataSource={evidence.samples || []}
                onChange={(pagination) => setEvidencePage({
                  pageSize: pagination.pageSize || 20,
                  current: pagination.current || 1,
                })}
                pagination={{
                  ...evidencePage,
                  showSizeChanger: true,
                  pageSizeOptions: ['10', '20', '50', '100'],
                  showTotal: (n) => `共 ${n} 条`,
                }}
                columns={[
                  { title: '时间', dataIndex: 'ts', width: 156, render: (v) => fmtTs(v) },
                  { title: '源 IP', dataIndex: 'src_ip', width: 120 },
                  {
                    title: '请求',
                    width: 240,
                    render: (_: any, s: RuleSample) => (
                      <Tooltip title={s.path}>
                        <Text code>{s.method} {s.path}</Text>
                      </Tooltip>
                    ),
                  },
                  { title: '字段', dataIndex: 'field', width: 70 },
                  {
                    title: '命中片段',
                    dataIndex: 'snippet',
                    ellipsis: true,
                    render: (v) => (v ? <Text code>{v}</Text> : '-'),
                  },
                  {
                    title: '模型',
                    width: 110,
                    render: (_: any, s: RuleSample) => (
                      <Space size={2} wrap>
                        {s.supervised_flagged ? <Tag color="volcano">监督</Tag> : null}
                        {s.zero_day_flagged ? <Tag color="gold">零日</Tag> : null}
                        {!s.supervised_flagged && !s.zero_day_flagged ? <span className="muted">-</span> : null}
                      </Space>
                    ),
                  },
                  {
                    title: '人工结论',
                    dataIndex: 'verdict',
                    width: 110,
                    render: (v: string | null) =>
                      v ? <Tag color={v === 'confirmed_attack' || v === 'missed' ? 'red' : v === 'uncertain' ? 'gold' : 'green'}>
                        {VERDICT_LABEL[v] || v}
                      </Tag> : <span className="muted">未标注</span>,
                  },
                  {
                    title: '标注',
                    width: 220,
                    render: (_: any, s: RuleSample) => (
                      <Space size={2} wrap>
                        <Button size="small" danger disabled={!canWrite} onClick={() => sampleFeedback(s, 'confirmed_attack')}>
                          确认攻击
                        </Button>
                        <Button size="small" disabled={!canWrite} onClick={() => sampleFeedback(s, 'false_positive')}>
                          正常业务
                        </Button>
                        <Button size="small" disabled={!canWrite} onClick={() => sampleFeedback(s, 'uncertain')}>
                          待查
                        </Button>
                      </Space>
                    ),
                  },
                ]}
              />
            </Card>

            {(evidence.incidents || []).length ? (
              <Card size="small" title="④ 这条规则的误报事件" style={{ marginTop: 12 }}>
                <Table
                  size="small"
                  rowKey="id"
                  pagination={false}
                  dataSource={evidence.incidents}
                  columns={[
                    { title: '时间', dataIndex: 'opened_at', width: 156, render: (v) => fmtTs(v) },
                    { title: '原因', dataIndex: 'reason', render: (v) => REASON_LABEL[v] || v },
                    { title: '严重度', dataIndex: 'severity', width: 84, render: (v) => <Tag color={SEVERITY_COLOR[v]}>{v}</Tag> },
                    { title: '状态', dataIndex: 'status', width: 86 },
                  ]}
                />
              </Card>
            ) : null}
          </div>
        ) : (
          <div className="muted">{evidenceLoading ? '加载中…' : '没有证据'}</div>
        )}
      </Drawer>

      {/* ---------------------------------------------------- 紧急熔断 */}
      <Modal
        open={breakerOpen}
        title="紧急熔断"
        okText="立即执行"
        okButtonProps={{ danger: true }}
        confirmLoading={busy === 'breaker'}
        onCancel={() => setBreakerOpen(false)}
        onOk={async () => {
          const v = await breakerForm.validateFields()
          await applyBreaker(v.scope, v.rule || null, v.reason || 'manual')
          setBreakerOpen(false)
        }}
        width={620}
      >
        <Alert
          type="warning"
          showIcon
          style={{ marginBottom: 12 }}
          message="熔断只降动作、不停采集；5 秒内热重载。"
          description="单规则：block→alert（alert 规则→移出现役）；全部阻断：所有 block→alert；通道：rules.enabled=false。恢复在「误报 / 熔断」页。"
        />
        <Form form={breakerForm} layout="vertical" size="small">
          <Form.Item name="scope" label="范围" rules={[{ required: true }]}>
            <Select
              options={[
                { value: 'rule', label: '单条规则' },
                { value: 'all_block', label: '全部阻断规则 → alert' },
                { value: 'channel', label: '关闭整个规则通道' },
              ]}
            />
          </Form.Item>
          <Form.Item noStyle shouldUpdate={(a, b) => a.scope !== b.scope}>
            {({ getFieldValue }) =>
              getFieldValue('scope') === 'rule' ? (
                <Form.Item name="rule" label="规则 id" rules={[{ required: true, message: '填规则 id' }]}>
                  <Input placeholder="例如 custom_waf_sqli_001 或 sqli_tautology" />
                </Form.Item>
              ) : null
            }
          </Form.Item>
          <Form.Item name="reason" label="原因">
            <Select
              options={[
                { value: 'manual', label: '手动处置' },
                { value: 'confirmed_fp', label: '人工确认误报' },
                { value: 'noise', label: '告警噪声' },
                { value: 'hit_spike', label: '命中量突增' },
                { value: 'block_spike', label: '阻断量突增' },
              ]}
            />
          </Form.Item>
          <Form.Item name="note" label="备注">
            <Input.TextArea rows={2} maxLength={300} placeholder="写清为什么现在熔断" />
          </Form.Item>
        </Form>
      </Modal>

      {/* ---------------------------------------------------- 提升弹窗 */}
      <Modal
        open={promoteOpen}
        title="提升到现役规则集"
        onCancel={() => setPromoteOpen(false)}
        width={860}
        footer={
          <Space>
            <Button onClick={() => setPromoteOpen(false)}>关闭</Button>
            <Button onClick={doPreview} loading={busy === 'preview'} disabled={!!promoteRes}>
              预览
            </Button>
            <Button
              type="primary"
              danger
              onClick={doPromote}
              loading={promoting}
              disabled={!!promoteRes || !isAdmin}
            >
              确认提升
            </Button>
          </Space>
        }
      >
        <Alert
          type="warning"
          showIcon
          style={{ marginBottom: 12 }}
          message="提升会重跑标定：规则在标定池上的阻断误报（Wilson 95% 上界）从监督目标里扣掉，融合 FPR 维持不变。"
          description={
            <span>
              测试中的规则会以 alert 进现役（参与判定、产生告警、不占预算）；只有已确认合格的规则才可能 block。
              顺序：编译校验 → 宽良性池预检 → 写现役规则集 → 重跑 thresholds.py → 重导出 testvec。
              任何一步失败都会<b>自动回滚</b>。
            </span>
          }
        />
        <Form form={promoteForm} layout="inline" size="small" style={{ marginBottom: 12 }}>
          <Form.Item name="min_weight_to_block" label="阻断线">
            <InputNumber min={0.1} max={20} step={0.1} style={{ width: 100 }} />
          </Form.Item>
          <Form.Item name="rule_budget_cap" label="预算上限（比例）">
            <InputNumber min={0.0001} max={0.05} step={0.0005} style={{ width: 130 }} />
          </Form.Item>
          <Form.Item name="note" label="备注" style={{ minWidth: 260 }}>
            <Input placeholder="为什么提升" maxLength={120} />
          </Form.Item>
        </Form>

        {preview ? (
          <>
            <Divider style={{ margin: '8px 0' }} />
            <div style={{ marginBottom: 8 }}>
              将写入 <Text code>artifacts/rules_authoritative.json</Text>：
              <Tag color="green" style={{ marginLeft: 8 }}>
                {preview?.ruleset?.rules?.length ?? 0} 条
              </Tag>
              <Tag color="red">block {preview?.ruleset?.counts?.block ?? 0} 条</Tag>
              <Tag>alert {preview?.ruleset?.counts?.alert ?? 0} 条</Tag>
              {preview?.ruleset?.counts?.testing ? (
                <Tag color="gold">测试 {preview.ruleset.counts.testing} 条</Tag>
              ) : null}
              {preview?.ruleset?.counts?.breaker ? (
                <Tag color="red">熔断 {preview.ruleset.counts.breaker} 条</Tag>
              ) : null}
            </div>
            <Table
              size="small"
              rowKey="id"
              pagination={false}
              dataSource={preview?.ruleset?.rules || []}
              columns={[
                { title: '规则', dataIndex: 'id', width: 220, render: (v: string) => <Text code>{v}</Text> },
                { title: '来源', dataIndex: 'source', width: 90 },
                { title: '权重', dataIndex: 'weight', width: 70, align: 'right' as const },
                {
                  title: '动作',
                  dataIndex: 'action',
                  width: 90,
                  render: (v: string) => <Tag color={v === 'block' ? 'red' : 'gold'}>{v}</Tag>,
                },
                {
                  title: '资格',
                  width: 120,
                  render: (_: any, x: any) =>
                    x?.provenance?.qualification === 'testing' ? (
                      <Tag color="gold">测试中</Tag>
                    ) : x?.provenance?.action_forced === 'breaker' ? (
                      <Tag color="red">熔断</Tag>
                    ) : (
                      <Tag color="green">合格</Tag>
                    ),
                },
                { title: '范围', dataIndex: 'scopes', render: (v: string[]) => (v || []).join(', ') },
              ]}
            />
          </>
        ) : null}

        {promoteRes ? (
          <>
            <Divider style={{ margin: '8px 0' }} />
            <Alert
              type="success"
              showIcon
              message={`已提升：ruleset_sha1_16 = ${promoteRes?.ruleset_sha1_16}`}
              description={
                <Descriptions
                  size="small"
                  column={2}
                  items={[
                    {
                      key: 'b1',
                      label: '宽良性池预检 FPR（上界）',
                      children: (
                        <span>
                          {fmtPct(promoteRes?.budget?.fpr_broad_pool_upper_95, 4)}
                          <span className="muted">
                            {' '}
                            （{fmtInt(promoteRes?.budget?.benign_hits)}/{fmtInt(promoteRes?.budget?.benign_n)}）
                          </span>
                        </span>
                      ),
                    },
                    {
                      key: 'b2',
                      label: '标定池扣减',
                      children: fmtPct(promoteRes?.budget?.fpr_calibration_pool_deducted, 4),
                    },
                    {
                      key: 'b3',
                      label: '监督目标 FPR',
                      children: (
                        <span>
                          {fmtPct(promoteRes?.budget?.sup_target_before, 3)} →{' '}
                          <b>{fmtPct(promoteRes?.budget?.sup_target_after, 3)}</b>
                        </span>
                      ),
                    },
                    {
                      key: 'b4',
                      label: '预算上限',
                      children: fmtPct(promoteRes?.budget?.cap, 3),
                    },
                  ]}
                />
              }
            />
            {promoteRes?.checklist?.channel_warning ? (
              <Alert
                type="warning"
                showIcon
                style={{ marginTop: 8 }}
                message={promoteRes.checklist.channel_warning}
              />
            ) : null}
            <div className="muted" style={{ marginTop: 8 }}>
              testvec 已重导出。<b>请重跑 Rust 门禁</b>（<Text code>rust\build.bat run --release</Text>）；
              采集器会在下一个轮询周期（默认 5s）自动热重载，无需重启。
            </div>
          </>
        ) : null}
      </Modal>
    </div>
  )
}
