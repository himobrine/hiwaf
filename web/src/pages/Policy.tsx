import { useCallback, useEffect, useState } from 'react'
import {
  Alert,
  Button,
  Card,
  Col,
  Descriptions,
  Divider,
  Input,
  Modal,
  Row,
  Select,
  Space,
  Switch,
  Table,
  Tag,
  Typography,
  message,
} from 'antd'
import { ReloadOutlined } from '@ant-design/icons'
import { api, fmtNum, fmtPct, fmtTs } from '../api'
import type { User } from '../types'

const { Title, Text, Paragraph } = Typography

export default function Policy({ user }: { user: User }) {
  const isAdmin = user.role === 'admin'
  const [data, setData] = useState<any>(null)
  const [err, setErr] = useState('')
  const [loading, setLoading] = useState(false)

  const [pool, setPool] = useState('csic')
  const [fpr, setFpr] = useState('0.01')
  const [zeroDay, setZeroDay] = useState('off')
  const [preview, setPreview] = useState<any>(null)
  const [previewLog, setPreviewLog] = useState('')
  const [busy, setBusy] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    setErr('')
    try {
      setData(await api<any>('/api/policy'))
    } catch (e: any) {
      setErr(e?.message || '加载失败')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    load()
  }, [load])

  const pol = data?.policy || {}

  const doPreview = async () => {
    setBusy(true)
    setPreview(null)
    setPreviewLog('')
    try {
      const r = await api<any>('/api/policy/preview', {
        method: 'POST',
        body: { pool, fpr, zero_day: zeroDay },
      })
      setPreview(r.policy)
      setPreviewLog(r.log || '')
    } catch (e: any) {
      message.error(e?.message || '预览失败')
    } finally {
      setBusy(false)
    }
  }

  const doPromote = () => {
    Modal.confirm({
      title: '确认提升为现役策略？',
      content: (
        <div>
          <Paragraph>
            将重跑 <Text code>thresholds.py</Text> 写入 <Text code>artifacts/decision_policy.json</Text>
            ，并刷新 <Text code>testvec.json</Text>。
          </Paragraph>
          <Paragraph type="danger">
            提升后建议重跑 Rust 门禁（<Text code>rust\build.bat run --release</Text>）核对 testvec。
            采集器会在 5s 内热重载新策略/规则集，<b>无需重启</b>（换模型产物才需重启）。
          </Paragraph>
        </div>
      ),
      okText: '提升',
      okButtonProps: { danger: true },
      onOk: async () => {
        try {
          const r = await api<any>('/api/policy/promote', {
            method: 'POST',
            body: { pool, fpr, zero_day: zeroDay, note: '控制台提升' },
          })
          message.success(`已提升为 v${r.policy?.version}`);
          setPreview(null)
          load()
        } catch (e: any) {
          message.error(e?.message || '提升失败')
        }
      },
    })
  }

  const toggleZeroDay = (on: boolean) => {
    Modal.confirm({
      title: on ? '开启零日通道？' : '关闭零日通道（安全降级）？',
      content: on
        ? '跨分布误报尚未在真实本地良性上验证；开启后零日通道会参与融合并产生 alert（不阻断）。'
        : '关闭后零日分数仍计算、原始穿阈仍留证，但不产生 alert。',
      okButtonProps: on ? { danger: true } : undefined,
      onOk: async () => {
        try {
          const r = await api<any>('/api/policy/zero-day', {
            method: 'POST',
            body: { enabled: on },
          })
          message.success(`已${on ? '开启' : '关闭'}，策略 v${r.policy?.version}`)
          load()
        } catch (e: any) {
          message.error(e?.message || '操作失败')
        }
      },
    })
  }

  return (
    <div>
      <div className="toolbar">
        <Title level={4} className="page-title">
          策略中心
        </Title>
        <Button icon={<ReloadOutlined />} onClick={load} loading={loading}>
          刷新
        </Button>
      </div>

      {err ? <Alert type="error" message={err} showIcon style={{ marginBottom: 12 }} /> : null}
      {(data?.warnings || []).map((w: string, i: number) => (
        <Alert key={i} type="warning" message={w} showIcon style={{ marginBottom: 8 }} />
      ))}

      <Row gutter={[12, 12]}>
        <Col xs={24} lg={12}>
          <Card size="small" title={`现役策略 v${pol.version ?? '-'}`}>
            <Descriptions size="small" column={1} bordered>
              <Descriptions.Item label="生成时间">{pol.generated_at || '-'}</Descriptions.Item>
              <Descriptions.Item label="生成脚本">{pol.generated_by || '-'}</Descriptions.Item>
              <Descriptions.Item label="融合方式">{pol.fusion?.policy || '-'}</Descriptions.Item>
              <Descriptions.Item label="监督阈值">
                <Text code>{fmtNum(pol.supervised?.threshold, 6)}</Text>{' '}
                <span className="muted">目标 FPR {pol.supervised?.target_fpr}</span>
              </Descriptions.Item>
              <Descriptions.Item label="零日阈值">
                <Text code>{fmtNum(pol.zero_day?.threshold, 6)}</Text>{' '}
                <span className="muted">目标 FPR {pol.zero_day?.target_fpr}</span>
              </Descriptions.Item>
              <Descriptions.Item label="零日通道">
                {isAdmin ? (
                  <Space>
                    <Switch
                      checked={!!pol.zero_day_enabled}
                      onChange={toggleZeroDay}
                      checkedChildren="开"
                      unCheckedChildren="关"
                    />
                    <Tag color={pol.zero_day_enabled ? 'red' : 'default'}>
                      {pol.zero_day_enabled ? '参与融合' : '安全降级'}
                    </Tag>
                  </Space>
                ) : (
                  <Tag color={pol.zero_day_enabled ? 'red' : 'default'}>
                    {pol.zero_day_enabled ? '开启' : '关闭（安全降级）'}
                  </Tag>
                )}
              </Descriptions.Item>
              <Descriptions.Item label="标定池">
                {pol.calibration_pool?.name || '-'}（n={pol.calibration_pool?.n ?? '-'}，同源重叠{' '}
                {pol.calibration_pool?.n_overlap ?? '-'}）
              </Descriptions.Item>
              <Descriptions.Item label="池上实测 FPR">
                监督 {fmtPct(pol.supervised?.actual_fpr?.[pol.supervised?.target_fpr], 3)}｜零日{' '}
                {fmtPct(pol.zero_day?.actual_fpr?.[pol.zero_day?.target_fpr], 3)}
              </Descriptions.Item>
              <Descriptions.Item label="融合池上 FPR / 生效 FPR">
                {fmtPct(pol.union_fpr_on_pool, 3)} / {fmtPct(pol.effective_fused_fpr_on_pool, 3)}
              </Descriptions.Item>
            </Descriptions>
            <Paragraph className="muted" style={{ marginTop: 8 }}>
              阈值不允许在界面上手改：只能「选标定池 → 预览 → 提升」，计算始终由 thresholds.py 完成。
            </Paragraph>
          </Card>
        </Col>

        <Col xs={24} lg={12}>
          <Card size="small" title="重标定（预览 / 提升）">
            <Space direction="vertical" style={{ width: '100%' }} size="middle">
              <div>
                <div className="muted">标定池</div>
                <Input
                  value={pool}
                  onChange={(e) => setPool(e.target.value)}
                  placeholder="csic / lexical / file:..\traindata\local\local_lab_benign.jsonl"
                />
              </div>
              <Space>
                <div>
                  <div className="muted">目标 FPR</div>
                  <Select
                    value={fpr}
                    onChange={setFpr}
                    style={{ width: 120 }}
                    options={[
                      { value: '0.001', label: '0.1%' },
                      { value: '0.01', label: '1%' },
                      { value: '0.03', label: '3%' },
                    ]}
                  />
                </div>
                <div>
                  <div className="muted">零日通道</div>
                  <Select
                    value={zeroDay}
                    onChange={setZeroDay}
                    style={{ width: 120 }}
                    options={[
                      { value: 'off', label: '关闭' },
                      { value: 'on', label: '开启' },
                    ]}
                  />
                </div>
              </Space>
              <Space>
                <Button type="primary" onClick={doPreview} loading={busy} disabled={!isAdmin}>
                  预览
                </Button>
                <Button danger onClick={doPromote} disabled={!isAdmin}>
                  提升为现役
                </Button>
                {!isAdmin ? <span className="muted">需要 admin</span> : null}
              </Space>
            </Space>

            {preview ? (
              <>
                <Divider />
                <Alert
                  type="success"
                  showIcon
                  message={`预览结果（未生效）：监督 ${fmtNum(
                    preview.supervised?.threshold,
                    6,
                  )}｜零日 ${fmtNum(preview.zero_day?.threshold, 6)}`}
                  description={
                    <span className="muted">
                      池上 FPR：监督 {fmtPct(preview.supervised?.actual_fpr?.[fpr], 3)}｜零日{' '}
                      {fmtPct(preview.zero_day?.actual_fpr?.[fpr], 3)}｜融合{' '}
                      {fmtPct(preview.union_fpr_on_pool, 3)} → 生效{' '}
                      {fmtPct(preview.effective_fused_fpr_on_pool, 3)}
                    </span>
                  }
                />
                {previewLog ? <pre className="pre-wrap">{previewLog}</pre> : null}
              </>
            ) : null}
          </Card>
        </Col>
      </Row>

      <Card size="small" title="策略版本历史" style={{ marginTop: 12 }}>
        <Table
          size="small"
          rowKey="version"
          pagination={false}
          dataSource={data?.versions || []}
          columns={[
            { title: '版本', dataIndex: 'version', width: 90, render: (v) => `v${v}` },
            { title: '操作人', dataIndex: 'actor', width: 140 },
            { title: '时间', dataIndex: 'created_at', width: 180, render: (v) => fmtTs(v) },
            { title: '备注', dataIndex: 'note' },
          ]}
        />
      </Card>
    </div>
  )
}
