# WAF 控制台前端（`web/`）

React 18 + TypeScript + Ant Design 5 + ECharts，Vite 构建。

定位：**安全运营业务层**（事件/告警/策略/反馈/规则/模型/任务/审计）。
基础设施运维指标（CPU、内存、QPS、延迟）仍由 Grafana + Prometheus 承担，这里不重复。

## 运行

```bash
# 1) 后端
cd F:\waf\python
py -3.10 -m service.run                 # 8090

# 2) 前端（开发）
cd F:\waf\web
npm install
npm run dev                             # 5173，/api 已代理到 8090

# 3) 生产（单端口）
npm run build                           # 产物 web/dist
# 之后访问 http://127.0.0.1:8090 即可，FastAPI 会托管 dist
```

初始账号见 `python/service/.admin_password`。

## 构建与拆包

- **路由级懒加载**：`src/App.tsx` 用 `React.lazy` + `Suspense`，首屏只加载总览，其余页面按路由下载。
- **第三方分包**：`vite.config.ts` 的 `manualChunks` 把 `react` / `antd` 拆成稳定 chunk；
  业务改动不会让这两个大包缓存失效。
- **ECharts 按需**：统一在 `src/echarts.ts` 注册实际用到的图表与组件
  （bar / pie / line / tree + grid / tooltip / legend / title + canvas）。
  新增图表类型时**只改这一处**，不要在页面里 `import 'echarts-for-react'`（会打进全量 ECharts）。
- 当前构建产物：`antd ≈ 1.15 MB`、`echarts ≈ 578 KB`（仅图表页加载）、
  各路由 chunk 2–56 KB、入口 `index ≈ 20 KB`。
- 构建后自检：`npm run typecheck && npm run build`；浏览器打开 `/` 与 `/#/models`，
  确认控制台无报错、代际树正常渲染。

## 页面

| 路由 | 页面 | 说明 |
| --- | --- | --- |
| `/` | 总览 | 计数卡片、**站点→模型**、分数直方图、攻击类型、策略摘要、采集器指标、入库状态、warnings |

**站点 → 模型**（一个 WAF 接多站点时最常被问到的那一格）：按窗口内每条判决的
`host` + `policy_version` 归组，用 `policy_versions` 快照里的产物 sha1 还原「这个站点的流量是谁在判」，
名称从 `model_registry` 解析；`状态` 直接给出与现役的差异（与现役一致 / 策略修订落后 /
模型落后 / 窗口内无判决 / 无法对比），悬停有解释。展开行可看该站点用过的每个修订各跑了什么模型。
纯展示，不改任何状态。
| `/events` | 事件 | 过滤 + **游标翻页**（上一页/下一页/页大小）；点开抽屉看**完整取证**（字段 / TreeSHAP Top-8 / 同源关联 / 反馈 / body） |
| `/alerts` | 告警 | 按源 IP + 动作 + 路径 + 时间桶聚合，可确认/关闭；点击行下钻查看该组原始流量，事件行可打开完整详情 |
| `/policy` | 策略中心 | 现役阈值、版本历史、**预览 → 提升**、零日通道开关 |
| `/feedback` | 反馈台账 | 人工结论列表 + 导出 JSON |
| `/rules` | 规则管理 | `rule_candidates.json` 的评审结论 + 启停 |
| `/models` | 模型与门禁 | 产物 sha1、训练元数据、**模型代际传承树**、学习曲线、保留策略 |
| `/tasks` | 训练任务 | 白名单任务 + 2s 轮询日志 |
| `/degradation` | 降级状态 | dry-run / 零日开关 / 阈值 / 降级备忘 |
| `/audit` | 审计 | 登录、策略、开关、body 查看等留痕（admin） |

**模型代际传承树**（`/models`）：每个通道一棵树，父代在上、子代在下；节点颜色 = 状态
（现役 / 候选 / 历史 / 已清理），蓝色连线 = 现役这条血脉，空心虚线 = 快照已清理
（只留元数据与血缘）。悬停看模型名与继承方式，点击节点看该代的血缘链、子代与切换记录。
多根（父代缺失 / 成环）会自动加一个通道虚拟根并在图下提示。数据直接取自
`/api/models` 的 `lineage` 字段，前端不二次请求；树高随代际深度自适应。

**事件页翻页**：用 keyset 游标（`cursor_ts` + `cursor_id`），不是 `offset`。前端把每页起点
游标存在 `cursorsRef`，点「上一页」直接用上一页的游标重查，点「下一页」用响应里的
`next_cursor`；深翻页不会因为 `offset` 变大而变慢。总数只在第一页统计
（`with_total=true`），翻页带 `with_total=false`，底部显示「共 N 条（第一页统计）」。
改过滤条件 / 页大小时会重置游标栈。行顺序固定为 `ts DESC, id DESC`，同毫秒事件也不会重复或漏掉。

## 刷新策略

按要求用**手动 / 定时轮询**，不用 SSE：

| 位置 | 周期 |
| --- | --- |
| 总览 | 手动（可选 15s 自动） |
| 顶栏运行模式 | 30s |
| 任务日志 | 2s（任务结束即停） |
| 其余表格 | 手动刷新按钮 |

## 红线（前端不要越线）

1. **没有自由编辑阈值的输入框**。策略页只有「选池 → 预览 → 提升」。
2. **dry-run 状态必须显著**：顶栏标签 + 总览 + 降级页三处都有。
3. **零日开关可见可切**（admin），并解释"关闭时分数仍留证、只是不产生 alert"。
4. **body 需要单独权限，且每次查看都写审计**；viewer 看不到入口。
5. **反馈是独立台账**：文案明确写"不覆盖 pred、不自动成为训练标签"。
