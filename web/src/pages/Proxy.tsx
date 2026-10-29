import { useCallback, useEffect, useRef, useState } from 'react'
import {
  Alert,
  Button,
  Card,
  Col,
  Descriptions,
  Form,
  Input,
  InputNumber,
  Popconfirm,
  Row,
  Select,
  Space,
  Switch,
  Tabs,
  Tag,
  Typography,
  message,
} from 'antd'
import {
  CaretRightOutlined,
  CopyOutlined,
  ReloadOutlined,
  SaveOutlined,
  StopOutlined,
} from '@ant-design/icons'
import { api, fmtBytes, fmtInt, fmtTs } from '../api'
import type { User } from '../types'

const { Title, Text, Paragraph } = Typography

function uptime(sec?: number | null) {
  if (sec === undefined || sec === null || sec < 0) return '-'
  const h = Math.floor(sec / 3600)
  const m = Math.floor((sec % 3600) / 60)
  const s = Math.floor(sec % 60)
  return h ? `${h}h ${m}m` : m ? `${m}m ${s}s` : `${s}s`
}

const GUIDE_REVERSE = `# 拓扑：客户端 -> 采集器 -> 真实后端
# 客户端访问采集器端口（默认 6188），采集器把请求转发到 --upstream。

# 1) 启动采集器（控制台「启动」或命令行）
cd F:\\waf\\proxy
call build.bat run --release -- ^
  --listen 127.0.0.1:6188 ^
  --upstream 127.0.0.1:80 ^
  --out ..\\traindata\\proxy ^
  --stats-out ..\\traindata\\proxy\\collector-metrics.json

# 2) 验证：请求应返回后端的响应，同时 raw-*.jsonl 多一条记录
curl -i "http://127.0.0.1:6188/?x=1"

# 3) 看指标：written 增长、dropped 为 0
curl -s "http://127.0.0.1:8091/api/proxy/status"

# 4) nginx 前置（可选）：客户端 -> nginx:80 -> 采集器:6188 -> 后端:8080
#    nginx 只做转发，不终止 TLS 时只能采 HTTP；HTTPS 需要 nginx 终止 TLS 后转 HTTP。
server {
    listen 80;
    location / {
        proxy_pass http://127.0.0.1:6188;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}`

const GUIDE_STEPS = `1. 在「采集代理」页确认 listen / upstream；保存配置。
2. 点「启动」。状态变为运行中，指标 written 开始增长。
3. 用 curl 或浏览器访问采集器端口，确认返回后端内容。
4. 到「事件」页看新事件；到「降级状态」页看 dry-run/纯采集模式。
5. 改配置后页面会提示「需重启生效」；点「重启」。
6. 停止：点「停止」。外部/未托管进程需要「强停」并二次确认。`

const GUIDE_TROUBLE = `端口被占用：改 listen，或停掉占用端口的进程；启动接口会返回 409。
502/连接失败：upstream 写错或后端没起；采集器只转发，不负责拉起后端。
有请求但事件页没有：确认 out_dir 固定为 traindata/proxy，且控制台 ingest 在跑；
  再看 /api/proxy/status 的 metrics.written 是否增长。
HTTPS 拿不到 body：监听侧不做 TLS 终止/CONNECT；在 nginx/Caddy 终止 TLS 后转 HTTP 给采集器。
指标 stale：进程可能卡住或已退出；看日志尾部，必要时重启。
找不到采集器：先 cd F:\\waf\\proxy && build.bat build --release。`

export default function Proxy({ user }: { user: User }) {
  const isAdmin = user.role === 'admin'
  const [st, setSt] = useState<any>(null)
  const [cfgView, setCfgView] = useState<any>(null)
  const [err, setErr] = useState('')
  const [loading, setLoading] = useState(false)
  const [busy, setBusy] = useState('')
  const [log, setLog] = useState('')
  const [logPath, setLogPath] = useState('')
  const [form] = Form.useForm()
  const formLoaded = useRef(false)

  const loadStatus = useCallback(async () => {
    try {
      setSt(await api<any>('/api/proxy/status'))
      setErr('')
    } catch (e: any) {
      setErr(e?.message || '加载失败')
    }
  }, [])

  const loadConfig = useCallback(async () => {
    try {
      const r = await api<any>('/api/proxy/config')
      setCfgView(r)
      if (!formLoaded.current) {
        form.setFieldsValue(r.config)
        formLoaded.current = true
      }
      setErr('')
    } catch (e: any) {
      setErr(e?.message || '加载配置失败')
    }
  }, [form])

  const loadAll = useCallback(async () => {
    setLoading(true)
    await Promise.all([loadStatus(), loadConfig()])
    setLoading(false)
  }, [loadStatus, loadConfig])

  useEffect(() => {
    loadAll()
  }, [loadAll])

  useEffect(() => {
    const t = setInterval(loadStatus, 5000)
    return () => clearInterval(t)
  }, [loadStatus])

  const loadLog = useCallback(async () => {
    try {
      const r = await api<any>('/api/proxy/log?tail=200')
      setLog(r.log || '')
      setLogPath(r.path || '')
    } catch (e: any) {
      setLog(`读取日志失败：${e?.message || e}`)
    }
  }, [])

  useEffect(() => {
    loadLog()
    if (!st?.running) return
    const t = setInterval(loadLog, 2000)
    return () => clearInterval(t)
  }, [st?.running, loadLog])

  const save = async () => {
    setBusy('save')
    try {
      const values = await form.validateFields()
      const r = await api<any>('/api/proxy/config', { method: 'PUT', body: values })
      setCfgView(r)
      message.success(r.restart_required
        ? `已保存；${r.restart_keys.join('、')} 需重启生效`
        : '已保存')
      await loadStatus()
    } catch (e: any) {
      if (e?.errorFields) return
      message.error(e?.message || '保存失败')
    } finally {
      setBusy('')
    }
  }

  const act = async (name: 'start' | 'stop' | 'restart', force = false) => {
    setBusy(name)
    try {
      await api<any>(`/api/proxy/${name}`, {
        method: 'POST',
        body: name === 'stop' ? { force } : undefined,
      })
      message.success(name === 'start' ? '已启动' : name === 'stop' ? '已停止' : '已重启')
      await Promise.all([loadStatus(), loadConfig()])
    } catch (e: any) {
      message.error(e?.message || '操作失败')
    } finally {
      setBusy('')
    }
  }

  const copy = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text)
      message.success('已复制')
    } catch {
      message.warning('浏览器拒绝访问剪贴板，请手动复制')
    }
  }

  const m = st?.metrics || null
  const running = !!st?.running
  const restartKeys: string[] = st?.restart_keys || []

  return (
    <div>
      <div className="toolbar">
        <Title level={4} className="page-title">
          采集代理
        </Title>
        <Space>
          <Button icon={<ReloadOutlined />} onClick={loadAll} loading={loading}>
            刷新
          </Button>
        </Space>
      </div>

      {err ? <Alert type="error" message={err} showIcon style={{ marginBottom: 12 }} /> : null}
      {(st?.warnings || []).map((w: string, i: number) => (
        <Alert key={i} type="warning" message={w} showIcon style={{ marginBottom: 8 }} />
      ))}
      {restartKeys.length ? (
        <Alert
          type="info"
          showIcon
          style={{ marginBottom: 12 }}
          message={`配置已保存，但以下项需重启采集器才生效：${restartKeys.join('、')}`}
        />
      ) : null}

      <Row gutter={12}>
        <Col xs={24} lg={14}>
          <Card
            size="small"
            title="运行状态"
            extra={
              <Space>
                {isAdmin ? (
                  <Button
                    type="primary"
                    icon={<CaretRightOutlined />}
                    disabled={running}
                    loading={busy === 'start'}
                    onClick={() => act('start')}
                  >
                    启动
                  </Button>
                ) : null}
                {isAdmin ? (
                  <Popconfirm
                    title="停止采集器？"
                    description="停止后业务流量将不再经过采集代理。"
                    onConfirm={() => act('stop')}
                    disabled={!running}
                  >
                    <Button
                      danger
                      icon={<StopOutlined />}
                      disabled={!running}
                      loading={busy === 'stop'}
                    >
                      停止
                    </Button>
                  </Popconfirm>
                ) : null}
                {isAdmin ? (
                  <Button
                    disabled={!running}
                    loading={busy === 'restart'}
                    onClick={() => act('restart')}
                  >
                    重启
                  </Button>
                ) : null}
                {isAdmin && running && !st?.managed ? (
                  <Popconfirm
                    title="强制停止未托管进程？"
                    description="PID 可能已被其他进程复用，确认后再强停。"
                    onConfirm={() => act('stop', true)}
                  >
                    <Button danger loading={busy === 'stop'}>
                      强停
                    </Button>
                  </Popconfirm>
                ) : null}
              </Space>
            }
          >
            <Descriptions size="small" bordered column={2}>
              <Descriptions.Item label="进程">
                <Tag color={running ? 'green' : 'default'}>{running ? '运行中' : '未运行'}</Tag>
                {running ? (
                  <Tag color={st?.managed ? 'blue' : 'orange'}>
                    {st?.managed ? '控制台托管' : '未托管'}
                  </Tag>
                ) : null}
              </Descriptions.Item>
              <Descriptions.Item label="PID / 运行时长">
                <Text code>{st?.pid ?? '-'}</Text> / {uptime(st?.uptime_sec)}
              </Descriptions.Item>
              <Descriptions.Item label="监听 → 上游" span={2}>
                <Text code>{st?.listen || '-'}</Text> → <Text code>{st?.upstream || '-'}</Text>
                <Tag style={{ marginLeft: 8 }} color={st?.port_listening ? 'green' : 'default'}>
                  {st?.port_listening ? '端口在监听' : '端口未监听'}
                </Tag>
              </Descriptions.Item>
              <Descriptions.Item label="指标" span={2}>
                {m ? (
                  <span>
                    {!running ? <Text type="secondary">上次运行指标：</Text> : null}
                    written <b>{fmtInt(m.written)}</b>，dropped(queue) <b>{fmtInt(m.dropped_queue_full)}</b>，
                    dropped(io) <b>{fmtInt(m.dropped_io)}</b>；allow {fmtInt(m.actions_allow)} /
                    alert {fmtInt(m.actions_alert)} / block {fmtInt(m.actions_block)}；更新{' '}
                    {fmtTs(m.ts)}{' '}
                    <Tag color={!running ? 'default' : m.stale ? 'red' : 'green'}>
                      {!running ? '上次运行' : m.stale ? '已过期' : '新鲜'}
                    </Tag>
                  </span>
                ) : (
                  <span className="muted">未读到指标文件（--stats-out）</span>
                )}
              </Descriptions.Item>
              <Descriptions.Item label="输出目录" span={2}>
                <Text code>{st?.out_dir?.path || '-'}</Text>；{fmtInt(st?.out_dir?.files)} 个文件，
                {fmtBytes(st?.out_dir?.bytes)}
                {st?.out_dir?.latest ? (
                  <span className="muted">（最新 {st.out_dir.latest.name}）</span>
                ) : null}
              </Descriptions.Item>
              <Descriptions.Item label="采集器二进制" span={2}>
                <Text code>{st?.binary?.path || '-'}</Text>{' '}
                <Tag color={st?.binary?.exists ? 'green' : 'red'}>
                  {st?.binary?.exists ? '已找到' : '缺失'}
                </Tag>
              </Descriptions.Item>
            </Descriptions>
            <Paragraph className="muted" style={{ marginTop: 12, marginBottom: 0 }}>
              采集器只采集、不阻断；<Text code>--score</Text> 仍是 dry-run。启动/停止/改配置都会写审计。
            </Paragraph>
          </Card>

          <Card
            size="small"
            title="日志"
            style={{ marginTop: 12 }}
            extra={
              <Space>
                <Text className="muted">{logPath || '暂无日志'}</Text>
                <Button size="small" icon={<ReloadOutlined />} onClick={loadLog}>
                  刷新
                </Button>
              </Space>
            }
          >
            <pre className="log-pre">{log || '（暂无日志；通过控制台启动后这里会出现采集器 stderr）'}</pre>
          </Card>
        </Col>

        <Col xs={24} lg={10}>
          <Card size="small" title="配置">
            <Form form={form} layout="vertical" disabled={!isAdmin} size="small">
              <Row gutter={8}>
                <Col span={12}>
                  <Form.Item name="listen" label="监听地址" rules={[{ required: true }]}>
                    <Input placeholder="127.0.0.1:6188" />
                  </Form.Item>
                </Col>
                <Col span={12}>
                  <Form.Item name="upstream" label="上游地址" rules={[{ required: true }]}>
                    <Input placeholder="127.0.0.1:80" />
                  </Form.Item>
                </Col>
              </Row>
              <Space size="large" wrap>
                <Form.Item name="upstream_tls" label="上游 TLS" valuePropName="checked">
                  <Switch />
                </Form.Item>
                <Form.Item name="score" label="dry-run 判定" valuePropName="checked">
                  <Switch />
                </Form.Item>
                <Form.Item name="no_body" label="隐私模式（不采 body）" valuePropName="checked">
                  <Switch />
                </Form.Item>
              </Space>
              <Row gutter={8}>
                <Col span={12}>
                  <Form.Item name="resp_body" label="响应体采样">
                    <Select
                      options={[
                        { value: 'alert', label: 'alert（只存告警/阻断）' },
                        { value: 'all', label: 'all（全存）' },
                        { value: 'off', label: 'off（不存）' },
                      ]}
                    />
                  </Form.Item>
                </Col>
                <Col span={12}>
                  <Form.Item name="file_size_mb" label="单文件轮转 (MB)">
                    <InputNumber min={1} max={4096} style={{ width: '100%' }} />
                  </Form.Item>
                </Col>
                <Col span={12}>
                  <Form.Item name="body_keep" label="body 落盘上限 (bytes)">
                    <InputNumber min={0} max={16 * 1024 * 1024} style={{ width: '100%' }} />
                  </Form.Item>
                </Col>
                <Col span={12}>
                  <Form.Item name="body_limit" label="body 缓冲上限 (bytes)">
                    <InputNumber min={1} max={64 * 1024 * 1024} style={{ width: '100%' }} />
                  </Form.Item>
                </Col>
                <Col span={12}>
                  <Form.Item name="headers_keep" label="头落盘上限 (bytes)">
                    <InputNumber min={1} max={8192} style={{ width: '100%' }} />
                  </Form.Item>
                </Col>
                <Col span={12}>
                  <Form.Item name="resp_body_keep" label="响应体上限 (bytes)">
                    <InputNumber min={1} max={65536} style={{ width: '100%' }} />
                  </Form.Item>
                </Col>
                <Col span={12}>
                  <Form.Item name="channel" label="写队列容量">
                    <InputNumber min={1} max={1000000} style={{ width: '100%' }} />
                  </Form.Item>
                </Col>
                <Col span={12}>
                  <Form.Item name="stats_interval" label="指标刷新 (秒)">
                    <InputNumber min={1} max={3600} style={{ width: '100%' }} />
                  </Form.Item>
                </Col>
                <Col span={12}>
                  <Form.Item name="reload_interval" label="热重载轮询 (秒，0=关)">
                    <InputNumber min={0} max={3600} style={{ width: '100%' }} />
                  </Form.Item>
                </Col>
              </Row>
              <Form.Item name="artifacts" label="模型产物目录">
                <Input placeholder="F:\\waf\\python\\artifacts" />
              </Form.Item>
              <Form.Item
                name="rules"
                label="规则集路径（留空 = 关闭规则通道）"
                extra="保存后需重启；策略/规则热重载仍按上面的轮询周期工作。"
              >
                <Input placeholder="F:\\waf\\python\\artifacts\\rules_authoritative.json" />
              </Form.Item>
              {isAdmin ? (
                <Button
                  type="primary"
                  icon={<SaveOutlined />}
                  onClick={save}
                  loading={busy === 'save'}
                  block
                >
                  保存配置
                </Button>
              ) : (
                <Alert type="info" showIcon message="只读：修改配置需要 admin。" />
              )}
              {cfgView?.effective ? (
                <Paragraph className="muted" style={{ marginTop: 12, marginBottom: 0 }}>
                  实际生效：{cfgView.effective.listen} → {cfgView.effective.upstream}；score=
                  {String(cfgView.effective.score)}；resp-body={cfgView.effective.resp_body}
                </Paragraph>
              ) : null}
            </Form>
          </Card>
        </Col>
      </Row>

      <Card size="small" title="接入指引" style={{ marginTop: 12 }}>
        <Tabs
          items={[
            {
              key: 'reverse',
              label: '反向代理前置',
              children: (
                <div>
                  <Paragraph>
                    推荐形态：客户端直接访问采集器端口，采集器转发到真实后端。HTTP 明文可以完整采集
                    body；HTTPS 需要在前面用 nginx/Caddy 终止 TLS 再转 HTTP。
                  </Paragraph>
                  <Button
                    size="small"
                    icon={<CopyOutlined />}
                    onClick={() => copy(GUIDE_REVERSE)}
                    style={{ marginBottom: 8 }}
                  >
                    复制命令
                  </Button>
                  <pre className="log-pre">{GUIDE_REVERSE}</pre>
                </div>
              ),
            },
            {
              key: 'steps',
              label: '控制台操作',
              children: <pre className="log-pre">{GUIDE_STEPS}</pre>,
            },
            {
              key: 'trouble',
              label: '故障排查',
              children: <pre className="log-pre">{GUIDE_TROUBLE}</pre>,
            },
          ]}
        />
      </Card>
    </div>
  )
}
