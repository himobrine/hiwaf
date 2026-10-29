export type Role = 'viewer' | 'analyst' | 'admin'

export interface User {
  id?: number
  username: string
  role: Role
}

export interface EventRow {
  id: number
  ts: number
  /** 这条事件的命中里有「未合格、测试中」的规则（命中会真的产生 alert）。 */
  rule_testing?: number
  src_ip?: string
  src_port?: number
  host?: string
  route?: string | null
  method?: string
  path?: string
  query?: string
  body_len?: number
  body_truncated?: number
  status?: number
  dur_ms?: number
  bytes_in?: number
  bytes_out?: number
  ua?: string
  referer?: string
  action?: 'block' | 'alert' | 'allow' | string | null
  supervised_score?: number | null
  supervised_threshold?: number | null
  supervised_flagged?: number
  zero_day_score?: number | null
  zero_day_threshold?: number | null
  zero_day_score_crossed?: number
  zero_day_flagged?: number
  zero_day_enabled?: number
  attack_label?: number | null
  attack_type?: string | null
  model_artifacts?: string
  dry_run?: number
  enforced?: number
  policy_version?: number
  rule_hits?: RuleHit[]
  rule_set_sha1_16?: string
}

/** 实体级误报抑制：只折叠控制台告警可见性，不改数据面判定。 */
export interface Suppression {
  id: number
  src_ip?: string | null
  path?: string | null
  ua?: string | null
  host?: string | null
  attack_type?: string | null
  reason: string
  status: 'draft' | 'active' | 'revoked' | 'expired'
  ttl_hours: number
  expires_at?: number | null
  created_by?: string | null
  created_at: number
  approved_by?: string | null
  approved_at?: number | null
  revoked_by?: string | null
  revoked_at?: number | null
  decision_note?: string | null
  note?: string | null
  updated_at?: number | null
}

export interface ShapItem {
  rank: number
  feature: string
  value: number
  contribution: number
}

/** 规则命中在**当前取证包文本**里的精确区间（UTF-16 字符下标，可直接 slice）。 */
export interface RuleSpan {
  /** method / path / query / body / ua / referer。 */
  field: string
  start: number
  end: number
}

/** 规则层命中（`pred.rule_hits` 侧证据，**不是**标签，不参与训练）。 */
export interface RuleHit {
  rule: string
  name?: string
  severity?: string
  action?: 'alert' | 'block'
  weight?: number
  /** 规则实际作用域：full / path / query / body / ua / referer。 */
  scope?: string
  /** 命中落在哪个字段：path / query / body / ua / referer（解码后按偏移回映射）。 */
  field?: string
  /** 规则作用域文本里的字节偏移。 */
  start?: number
  end?: number
  /** 命中片段（解码后，已截断）。 */
  snippet?: string
  /** 服务端算好的精确标位；老数据可能缺失，此时退回字段级。 */
  segments?: RuleSpan[]
}

export interface EventDetail extends EventRow {
  shap: ShapItem[]
  rule_hits?: RuleHit[]
  rule_set_sha1_16?: string
  has_body: boolean
  feedback: any[]
  related: any[]
}

/* ------------------------------------------------------------------ 取证包 */

/** raw 里保存的原始字节（base64） + 服务端解码结果。 */
export interface PacketBody {
  /** 原始存盘 wire bytes 的 base64；可能被 64KB 上限截断。 */
  b64: string
  /** 服务端按 Content-Encoding 逆序解压后的文本；二进制/解压失败时为 null。 */
  decoded_text: string | null
  decoded_encoding: string | null
  decoded_is_binary: boolean
  wire_bytes: number
  stored_bytes: number
  truncated: boolean
  decode_truncated: boolean
  /** `source_truncated` / `decode_failed` / `zstd_unsupported` / `br_unsupported` / `unsupported_encoding:*` */
  decode_error: string | null
  /** 从响应头解析出的编码链（原顺序）。 */
  content_encoding: string[]
  /** 旧 raw 只有文本 `body`，可能已 lossy；明确标记。 */
  legacy_lossy?: boolean
}

export interface PacketMessage {
  http_version?: string | null
  method?: string | null
  path?: string | null
  query?: string | null
  captured?: boolean
  status?: number | null
  /** 有序头数组；重复头逐个保留。顺序是解析后顺序，不是 wire order。 */
  headers: [string, string][]
  headers_total_bytes: number
  headers_stored_bytes: number
  headers_truncated: boolean
  sampling_mode?: string | null
  body_sampled: boolean
  body: PacketBody | null
  body_reason: string
  body_wire_bytes: number
  body_truncated: boolean
}

export interface EventPacket {
  event_id: number
  reconstructed: boolean
  reconstructed_reason: string | null
  header_order_note: string
  headers_count_basis: string
  request: PacketMessage
  response: PacketMessage
  /** 与服务端展示文本对齐的规则命中（含 segments 精确区间）。 */
  rule_hits?: RuleHit[]
  sensitive_headers: string[]
  masked_headers: string[]
}

/* ------------------------------------------------------------------ 规则通道 */

/** 历史告警回放证据（仅自撰规则；手动触发，规则一改即失效）。 */
export interface RuleHistory {
  rule: string
  rule_sha?: string
  days: number
  scanned: number
  truncated: number | boolean
  matched: number
  confirmed_attack: number
  confirmed_benign: number
  suspected_attack: number
  unlabeled: number
  samples: number[]
  last_ts?: number | null
  body?: any
  ok: boolean
  reason?: string
  actor?: string
  created_at?: number
}

/** 在线证据（真实运行数据，按来源分桶；模型只做「疑似」提示）。 */
export interface RuleOnline {
  rule: string
  /** 窗口内命中的事件数（不是命中行数）。 */
  hits: number
  block_hits: number
  /** 人工确认攻击（confirmed_attack / missed）。 */
  confirmed_attack: number
  /** 人工确认正常（confirmed_benign / false_positive）。 */
  confirmed_benign: number
  /** 没有人工标签，但监督/零日也报了 —— 只提示，不单独定罪。 */
  suspected_attack: number
  unlabeled: number
  last_ts?: number | null
}

export interface RuleBreaker {
  rule: string
  reason: string
  actor: string
  opened_at: number
  incident_id?: number | null
  prev_action?: string | null
  mode?: 'alert' | 'disable'
  note?: string | null
}

/** 一条规则（挖出的候选 或 自撰规则），控制台看到的合并视图。 */
export interface RuleRow {
  id: string
  name?: string
  regex: string
  scopes: string[]
  severity?: string
  weight: number
  /** `alert` = 只告警；`block` = 计入阻断预算（只有它能让规则通道拦人）。 */
  action: 'alert' | 'block'
  /** 用户本来想设的 action（非 keep 被夹紧成 alert 时，这里保留原值便于审计）。 */
  action_requested?: string
  /** `true` = 未合格 / 被熔断，action 被锁死为 alert。 */
  action_locked?: boolean
  /** 开关 = 参与判定（只告警）。**不等于合格**。 */
  enabled: boolean
  /** 实测证据等级（== verdict，永不因开关而改写）。 */
  evidence_grade?: string
  /** 挖出的候选：`proven` = 有攻击证据；`user_override` = 证据不足但用户要求启用。 */
  qualified?: 'proven' | 'user_override'
  /** 自撰规则：是否已人工确认合格（v2）。 */
  is_qualified?: boolean
  /** `true` = 已启用但证据不足（告警噪声来源）。 */
  overridden?: boolean
  /** `mined` = 挖出的候选；其余都来自 `rules_custom` 表（manual / crs / wafjson / custom）。 */
  source: 'mined' | 'manual' | 'crs' | 'wafjson' | 'custom'
  /** 显式类型：detector = 攻击检测型；guard = 防御型入口规则（合格不看攻击回放）。 */
  kind?: 'detector' | 'guard'
  /** 自撰规则的派生状态（不落库）。 */
  state?: 'uncompiled' | 'noisy' | 'ready' | 'testing' | 'suggest' | 'qualified' | string
  compiled?: boolean
  compiled_at?: number | null
  enabled_at?: number | null
  qualified_at?: number | null
  qualified_by?: string | null
  qualification_source?: string | null
  qualification_note?: string | null
  can_enable?: boolean
  can_block?: boolean
  suggest_qualified?: boolean
  blockers?: string[]
  online?: RuleOnline
  /** 历史告警回放证据（仅自撰规则；null/缺失 = 没跑过或规则已改）。 */
  history?: RuleHistory | null
  history_ok?: boolean
  breaker?: RuleBreaker | null
  /* 挖出的候选独有 */
  verdict?: string
  benign_hits?: number
  benign_n?: number
  benign_rate?: number
  attack_hits?: number
  attack_n?: number
  attack_rate?: number
  decoding_gain?: number
  pool_support?: number
  /* 自撰规则独有 */
  validated_at?: number | null
  validation?: {
    passed?: boolean
    failed_at?: string
    gates?: {
      regex_safety?: { passed?: boolean; stdout?: string; stderr?: string; error?: string }
      benign_replay?: {
        passed?: boolean | null
        benign_hits?: number
        benign_n?: number
        benign_rate?: number
        caveat?: string
      }
      attack_replay?: {
        passed?: boolean | null
        not_applicable?: boolean
        attack_hits?: number
        attack_n?: number
        attack_rate?: number
      }
    }
    regex?: { ok: boolean; error?: string | null }
    benign?: { hits?: number; n?: number; ok?: boolean; error?: string | null }
    attack?: { hits?: number; n?: number; ok?: boolean; error?: string | null }
    checked_at?: number
  } | null
  warnings?: string[]
  notes?: string
  created_at?: number
  updated_at?: number
  state_actor?: string
}

export interface RuleSample {
  event_id: number
  ts: number
  src_ip?: string
  method?: string
  path?: string
  action?: string
  supervised_score?: number | null
  supervised_flagged?: number
  zero_day_flagged?: number
  rule_testing?: number
  field?: string
  snippet?: string
  rule_weight?: number
  rule_action?: string
  /** 最新一条人工反馈；null = 未标注。 */
  verdict?: string | null
}

export interface RuleIncident {
  id: number
  rule?: string | null
  rule_name?: string | null
  scope: 'rule' | 'all_block' | 'channel' | string
  severity: 'high' | 'medium' | string
  status: 'open' | 'acked' | 'resolved' | string
  reason: string
  detail?: any
  opened_at: number
  opened_by?: string | null
  resolved_at?: number | null
  resolved_by?: string | null
  note?: string | null
}

export interface RuleEvidence {
  rule: string
  source: string
  name?: string
  kind: 'detector' | 'guard' | string
  state: string
  view?: any
  offline: any
  online: RuleOnline
  history?: RuleHistory | null
  history_ok?: boolean
  samples: RuleSample[]
  incidents: RuleIncident[]
  qualified_at?: number | null
  qualified_by?: string | null
  qualification_source?: string | null
  qualification_note?: string | null
}

export interface RulesAuthoritativeInfo {
  present: boolean
  sha1_16?: string | null
  ruleset_id?: string
  generated_at?: number
  decode?: string[]
  min_weight_to_block?: number
  counts?: {
    total: number
    block: number
    alert: number
    mined: number
    custom: number
    crs?: number
    wafjson?: number
    /** 「有攻击证据」与「用户强行启用」的拆分（审计用）。 */
    proven?: number
    user_override?: number
    /** 已启用但未合格的测试规则（强制 alert）。 */
    testing?: number
    /** 被熔断覆盖成 alert / 移出现役的规则数。 */
    breaker?: number
    by_verdict?: Record<string, number>
    by_kind?: Record<string, number>
  }
  mtime?: number
  note?: string
}

export interface RulesPayload {
  eval?: {
    benign_n?: number
    benign_sources?: string
    attack_n?: number
    attack_sources?: string
    decoding?: string
  }
  summary?: any
  counts?: Record<string, number>
  /** 启用口径汇总：多少条启用 / 其中多少条有攻击证据、多少条是用户强行放行。 */
  enabled?: {
    n_total: number
    n_enabled: number
    n_proven: number
    n_user_override: number
    n_disabled: number
  }
  /** 自撰/导入规则的状态机汇总（v2：启用 ≠ 合格）。 */
  custom_state?: {
    n_total: number
    n_enabled: number
    n_qualified: number
    n_testing: number
    n_ready: number
    n_noisy: number
    n_uncompiled: number
    n_suggest: number
    n_block: number
    n_blocked_by_breaker: number
    by_kind: Record<string, number>
  }
  rules: RuleRow[]
  custom: RuleRow[]
  authoritative?: RulesAuthoritativeInfo
  breakers?: RuleBreaker[]
  /** 误报扫描 / 自动熔断开关（`app_settings.rules.*`，下一轮扫描生效）。 */
  monitor?: { auto_breaker: boolean; breaker_alerts: boolean }
  decode: string[]
  scopes: string[]
  actions: string[]
  severities: string[]
  kinds?: string[]
  notes?: Record<string, string>
}

/** 策略里的规则块（`decision_policy.json.rules`）。 */
export interface PolicyRules {
  enabled?: boolean
  ruleset_path?: string
  ruleset_sha1_16?: string
  ruleset_id?: string
  min_weight_to_block?: number
  n_rules?: number
  n_block_rules?: number
  nominal_target_fpr?: number
  sup_target_fpr?: number
  budget_deducted?: number
  note?: string
}

/** 采集器热重载状态：「磁盘上的」vs「采集器在用的」。 */
export interface ReloadView {
  available: boolean
  reason?: string
  interval_sec?: number
  policy_disk_sha1_16?: string | null
  policy_seen_sha1_16?: string | null
  policy_active_revision?: number | null
  policy_revision?: number
  rules_disk_sha1_16?: string | null
  rules_seen_sha1_16?: string | null
  rules_active_sha1_16?: string | null
  rules_active_n?: number | null
  last_ok_ts?: number
  last_err_ts?: number
  last_err?: string | null
  /** 磁盘比「已看见」新：还没轮到下一个轮询周期 */
  policy_drift?: boolean
  rules_drift?: boolean
  /** 磁盘比「在用」新：轮询过但没换成 —— 这个是真问题 */
  rules_effective_drift?: boolean
}
