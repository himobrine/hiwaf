import { useEffect, useRef, useState } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { Badge, Button, Layout, Menu, Modal, Space, Tag, Tooltip, Typography, notification } from 'antd'
import {
  AlertOutlined,
  CloudServerOutlined,
  DashboardOutlined,
  DatabaseOutlined,
  EditOutlined,
  ExperimentOutlined,
  FileSearchOutlined,
  FilterOutlined,
  LogoutOutlined,
  PlayCircleOutlined,
  SafetyCertificateOutlined,
  StopOutlined,
  TeamOutlined,
  UnorderedListOutlined,
  WarningOutlined,
} from '@ant-design/icons'
import { api } from '../api'
import type { RuleIncident, User } from '../types'

const REASON_LABEL: Record<string, string> = {
  confirmed_fp: '人工确认误报',
  noise: '告警噪声',
  hit_spike: '命中量突增',
  block_spike: '阻断量突增',
  manual: '手动熔断',
}

function incidentSummary(inc: RuleIncident) {
  const d: any = inc.detail || {}
  const bits = [
    REASON_LABEL[inc.reason] || inc.reason,
    `${d.window_min ?? '?'} 分钟`,
    `命中 ${d.hits ?? d.blocks ?? '?'}`,
    `确认攻击 ${d.confirmed_attack ?? 0}`,
    `确认正常 ${d.confirmed_benign ?? 0}`,
  ]
  if (d.suspected_attack) bits.push(`疑似 ${d.suspected_attack}`)
  if (d.samples?.length) bits.push(`样本 #${d.samples.join(', #')}`)
  return bits.join('｜')
}

const { Header, Sider, Content } = Layout
const { Text } = Typography

export default function AppLayout({
  user,
  onLogout,
  children,
}: {
  user: User
  onLogout: () => void
  children: React.ReactNode
}) {
  const nav = useNavigate()
  const navRef = useRef(nav)
  navRef.current = nav
  const loc = useLocation()
  const [collapsed, setCollapsed] = useState(false)
  const [mode, setMode] = useState<string>('unknown')
  const [incidents, setIncidents] = useState<RuleIncident[]>([])

  /** 规则误报/熔断事件：有 open 时 5s 轮询，没有时 10s。
   *
   * 高严重度（自动熔断 / 大量确认误报）用 `Modal.error` 常驻，每个 incident 只弹一次
   * （localStorage 记「弹过」）；中严重度用 notification。**已阅 ≠ 关闭**：弹窗只负责
   * 让人看到，处置仍在规则页的「误报 / 熔断」里，避免弹窗一关就当没事。
   */
  useEffect(() => {
    let alive = true
    let timer: any = null
    const tick = async () => {
      try {
        const r = await api<any>('/api/rules/incidents?status=open&limit=50')
        if (!alive) return
        const items: RuleIncident[] = r?.items || []
        setIncidents(items)
        for (const inc of items) {
          const key = `waf_incident_seen_${inc.id}`
          try {
            if (localStorage.getItem(key)) continue
            localStorage.setItem(key, '1')
          } catch {
            /* localStorage 不可用时照常弹，只是可能重复 */
          }
          const who = inc.rule || '规则通道'
          const summary = incidentSummary(inc)
          if (inc.severity === 'high') {
            Modal.error({
              title: `规则误报熔断：${who}`,
              width: 600,
              content: (
                <div>
                  <p>{summary}</p>
                  <p>
                    系统已按「人工确认误报」自动把该规则降为只告警（如果它是 block 规则）。
                    规则本身没有被删除，证据继续留档；确认修好后可在规则页恢复。
                  </p>
                  <p className="muted" style={{ margin: 0 }}>
                    弹窗只弹一次；未处理状态会一直显示在「规则管理」的红点里。
                  </p>
                </div>
              ),
              okText: '去规则页处理',
              onOk: () => navRef.current('/rules'),
            })
          } else {
            notification.warning({
              message: `规则事件：${who}`,
              description: summary,
              duration: 10,
              onClick: () => navRef.current('/rules'),
            })
          }
        }
        timer = setTimeout(tick, items.length ? 5000 : 10000)
      } catch {
        if (alive) timer = setTimeout(tick, 15000)
      }
    }
    tick()
    return () => {
      alive = false
      if (timer) clearTimeout(timer)
    }
  }, [])

  useEffect(() => {
    let alive = true
    const tick = async () => {
      try {
        const r = await api<any>('/api/health/degradation')
        if (alive) setMode(r.mode || 'unknown')
      } catch {
        /* 保持上一次状态 */
      }
    }
    tick()
    const t = setInterval(tick, 30000)
    return () => {
      alive = false
      clearInterval(t)
    }
  }, [])

  const items: any[] = [
    { key: '/', icon: <DashboardOutlined />, label: '总览' },
    { key: '/events', icon: <UnorderedListOutlined />, label: '事件' },
    { key: '/alerts', icon: <AlertOutlined />, label: '告警' },
    { key: '/suppressions', icon: <StopOutlined />, label: '抑制策略' },
    { key: '/policy', icon: <SafetyCertificateOutlined />, label: '策略中心' },
    { key: '/feedback', icon: <EditOutlined />, label: '反馈台账' },
    {
      key: '/rules',
      icon: <FilterOutlined />,
      label: (
        <span>
          规则管理
          {incidents.length ? (
            <Badge count={incidents.length} size="small" style={{ marginLeft: 6 }} />
          ) : null}
        </span>
      ),
    },
    { key: '/models', icon: <ExperimentOutlined />, label: '模型与门禁' },
    { key: '/datasets', icon: <DatabaseOutlined />, label: '训练数据' },
    { key: '/tasks', icon: <PlayCircleOutlined />, label: '训练任务' },
    { key: '/degradation', icon: <WarningOutlined />, label: '降级状态' },
    { key: '/proxy', icon: <CloudServerOutlined />, label: '采集代理' },
  ]
  if (user.role === 'admin') {
    items.push({ key: '/audit', icon: <FileSearchOutlined />, label: '审计' })
    items.push({ key: '/users', icon: <TeamOutlined />, label: '用户管理' })
  }

  const modeTag =
    mode === 'enforce' ? (
      <Tooltip title="已开启真实拦截：命中 block 的请求返回 403。">
        <Tag color="red">拦截中（enforce）</Tag>
      </Tooltip>
    ) : mode === 'dry_run' ? (
      <Tooltip title="判定已接线，但只记录不阻断。需要拦截请在采集代理页切到 enforce。">
        <Tag color="orange">dry-run 只记录</Tag>
      </Tooltip>
    ) : mode === 'off' || mode === 'collect_only' ? (
      <Tooltip title="采集器未加载模型（block_mode=off）。">
        <Tag color="blue">纯采集</Tag>
      </Tooltip>
    ) : (
      <Tooltip title="未读到采集器指标文件（--stats-out）。">
        <Tag>采集器状态未知</Tag>
      </Tooltip>
    )

  return (
    <Layout style={{ minHeight: '100%' }}>
      <Sider collapsible collapsed={collapsed} onCollapse={setCollapsed} width={210}>
        <div
          style={{
            height: 56,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: '#fff',
            fontWeight: 600,
            letterSpacing: 1,
            cursor: 'pointer',
          }}
          onClick={() => nav('/')}
        >
          {collapsed ? 'WAF' : 'WAF 控制台'}
        </div>
        <Menu
          theme="dark"
          mode="inline"
          selectedKeys={[loc.pathname]}
          items={items}
          onClick={(e) => nav(e.key)}
        />
      </Sider>
      <Layout>
        <Header
          style={{
            background: '#fff',
            padding: '0 20px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            borderBottom: '1px solid #f0f0f0',
          }}
        >
          <Space>
            {modeTag}
            {incidents.length ? (
              <Tooltip title="规则误报/熔断事件；点这里去处置">
                <Tag color="red" style={{ cursor: 'pointer' }} onClick={() => nav('/rules')}>
                  规则事件 {incidents.length}
                </Tag>
              </Tooltip>
            ) : null}
          </Space>
          <Space size="middle">
            <Text>
              {user.username}
              <Tag style={{ marginLeft: 8 }} color="geekblue">
                {user.role}
              </Tag>
            </Text>
            <Button icon={<LogoutOutlined />} onClick={onLogout} size="small">
              退出
            </Button>
          </Space>
        </Header>
        <Content style={{ padding: 20, overflow: 'auto' }}>{children}</Content>
      </Layout>
    </Layout>
  )
}
