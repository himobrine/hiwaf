/**
 * ECharts 按需注册。
 *
 * 只引入项目实际用到的图表与组件，避免把整个 echarts 打进首屏：
 *   - 图表：bar（总览直方图 / SHAP 贡献）、pie（攻击类型）、line（模型曲线）、tree（代际树）
 *   - 组件：grid / tooltip / legend / title
 *   - 渲染器：canvas
 *
 * 新增图表类型时在这里补注册，并同步 3 个使用点（Overview / Models / EventDetailDrawer）。
 */
import * as echarts from 'echarts/core'
import { BarChart, LineChart, PieChart, TreeChart } from 'echarts/charts'
import {
  GridComponent,
  LegendComponent,
  TitleComponent,
  TooltipComponent,
} from 'echarts/components'
import { CanvasRenderer } from 'echarts/renderers'

echarts.use([
  BarChart,
  LineChart,
  PieChart,
  TreeChart,
  GridComponent,
  LegendComponent,
  TitleComponent,
  TooltipComponent,
  CanvasRenderer,
])

export default echarts
