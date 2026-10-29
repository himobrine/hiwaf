import { useCallback, useEffect, useState } from 'react'
import { Alert, Button, Card, Descriptions, Space, Tag, Typography } from 'antd'
import { ReloadOutlined } from '@ant-design/icons'
import { Link } from 'react-router-dom'
import { api, fmtNum, fmtTs } from '../api'

const { Title, Text, Paragraph } = Typography

export default function Degradation() {
  const [d, setD] = useState<any>(null)
  const [err, setErr] = useState('')
  const [loading, setLoading] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    setErr('')
    try {
      setD(await api<any>('/api/health/degradation'))
    } catch (e: any) {
      setErr(e?.message || '加载失败')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    load()
  }, [load])

  const col = d?.collector || null

  return (
    <div>
      <div className="toolbar">
        <Title level={4} className="page-title">
          降级状态
        </Title>
        <Button icon={<ReloadOutlined />} onClick={load} loading={loading}>
          刷新
        </Button>
      </div>

      {err ? <Alert type="error" message={err} showIcon style={{ marginBottom: 12 }} /> : null}
      {(d?.warnings || []).map((w: string, i: number) => (
        <Alert key={i} type="warning" message={w} showIcon style={{ marginBottom: 8 }} />
      ))}

      <Card size="small" title="当前运行态">
        <Descriptions size="small" bordered column={2}>
          <Descriptions.Item label="数据面模式">
            <Tag color={d?.mode === 'enforce' ? 'red' : d?.mode === 'dry_run' ? 'orange' : d?.mode === 'off' || d?.mode === 'collect_only' ? 'blue' : 'default'}>
              {d?.mode === 'enforce' ? '拦截中（enforce）' : d?.mode === 'dry_run' ? 'dry-run（只记录不阻断）' : d?.mode === 'off' || d?.mode === 'collect_only' ? '纯采集' : '未知'}
            </Tag>
          </Descriptions.Item>
          <Descriptions.Item label="零日通道">
            <Tag color={d?.zero_day_enabled ? 'red' : 'default'}>
              {d?.zero_day_enabled ? '开启（参与融合）' : '关闭（安全降级）'}
            </Tag>
          </Descriptions.Item>
          <Descriptions.Item label="监督阈值">
            <Text code>{fmtNum(d?.supervised_threshold, 6)}</Text>
          </Descriptions.Item>
          <Descriptions.Item label="零日阈值">
            <Text code>{fmtNum(d?.zero_day_threshold, 6)}</Text>
          </Descriptions.Item>
          <Descriptions.Item label="采集器指标" span={2}>
            {col ? (
              <span>
                监听 {col.listen} → 上游 {col.upstream}；时间 {fmtTs(col.ts)}{' '}
                <Tag color={col.stale ? 'red' : 'green'}>{col.stale ? '已过期' : '新鲜'}</Tag>
              </span>
            ) : (
              <span className="muted">未读到指标文件</span>
            )}
          </Descriptions.Item>
        </Descriptions>
        <Paragraph className="muted" style={{ marginTop: 12 }}>
          零日通道开关在 <Link to="/policy">策略中心</Link> 修改（需要 admin）。关闭时零日分数仍计算、
          原始穿阈仍留证，但不产生 alert。
        </Paragraph>
        <Space>
          <Link to="/policy">
            <Button type="primary">去策略中心</Button>
          </Link>
          <Link to="/models">
            <Button>查看门禁/曲线</Button>
          </Link>
        </Space>
      </Card>

      <Card size="small" title="降级决策备忘" style={{ marginTop: 12 }}>
        <ul>
          <li>
            <b>dry-run 是刻意默认</b>：上线模型在 payload_train + CSIC 上训练，训练集带 body 的记录是 0 条；
            真实本地良性池只有几百条，阈值分位抖动大。先用真实流量把阈值重标定，再谈拦截。
          </li>
          <li>
            <b>零日通道默认关闭</b>：跨分布误报不可控（lexical 28.2%）。它只产生 alert、不阻断。
          </li>
          <li>
            <b>阈值不属于 UI 状态</b>：唯一事实来源是 <Text code>artifacts/decision_policy.json</Text>，
            由 thresholds.py 生成；界面上只能预览/提升。
          </li>
          <li>
            <b>门禁不是可选项</b>：策略、testvec、Rust 三件套必须一起重新生成，否则 Rust 启动即断言失败。
          </li>
        </ul>
      </Card>
    </div>
  )
}
