<template>
  <div>
    <h3 class="page-title">{{ $t('menu.traffic') }}</h3>
    <div class="toolbar">
      <el-select v-model="iface" class="w-md" :aria-label="$t('common.iface')">
        <el-option v-for="n in names" :key="n" :label="n" :value="n" />
      </el-select>
      <span class="muted">{{ $t('traffic.sampling') }}</span>
    </div>
    <el-row :gutter="16" class="mb">
      <el-col :xs="24" :sm="12">
        <el-card shadow="never" class="stat-card rx">
          <div class="stat-label">{{ $t('traffic.rxLegend') }} {{ iface }}</div>
          <div class="stat-value">{{ fmtBytes(cur.rx, '/s') }}</div>
          <div class="stat-sub">{{ $t('traffic.peak', { v: fmtBytes(peak.rx, '/s') }) }}</div>
        </el-card>
      </el-col>
      <el-col :xs="24" :sm="12">
        <el-card shadow="never" class="stat-card tx">
          <div class="stat-label">{{ $t('traffic.txLegend') }} {{ iface }}</div>
          <div class="stat-value">{{ fmtBytes(cur.tx, '/s') }}</div>
          <div class="stat-sub">{{ $t('traffic.peak', { v: fmtBytes(peak.tx, '/s') }) }}</div>
        </el-card>
      </el-col>
    </el-row>
    <el-card shadow="never" class="mb">
      <!-- 下行画在 0 轴上方、上行画在下方（镜像），两条曲线不会互相遮挡 -->
      <v-chart :option="option" autoresize class="chart" />
    </el-card>
    <el-card shadow="never" :header="$t('traffic.all')">
      <el-table :data="table" size="small">
        <el-table-column prop="name" :label="$t('common.iface')" />
        <el-table-column :label="$t('common.rx')"><template #default="{ row }"><span class="c-rx">{{ fmtBytes(row.rx, '/s') }}</span></template></el-table-column>
        <el-table-column :label="$t('common.tx')"><template #default="{ row }"><span class="c-tx">{{ fmtBytes(row.tx, '/s') }}</span></template></el-table-column>
        <el-table-column :label="$t('traffic.rxTotal')"><template #default="{ row }">{{ fmtBytes(row.rxTotal) }}</template></el-table-column>
        <el-table-column :label="$t('traffic.txTotal')"><template #default="{ row }">{{ fmtBytes(row.txTotal) }}</template></el-table-column>
        <el-table-column prop="drop" :label="$t('interfaces.rxDrop')" />
      </el-table>
    </el-card>
  </div>
</template>

<script setup>
import { computed, onBeforeUnmount, onMounted, ref, shallowRef } from 'vue'
import VChart from 'vue-echarts'
import { use } from 'echarts/core'
import { LineChart } from 'echarts/charts'
import { GridComponent, LegendComponent, MarkLineComponent, TooltipComponent } from 'echarts/components'
import { CanvasRenderer } from 'echarts/renderers'
import { api, fmtBytes } from '../api'
import { isMobile } from '../viewport'
import { t } from '../i18n'

use([LineChart, GridComponent, LegendComponent, MarkLineComponent, TooltipComponent, CanvasRenderer])

const MAX = 150
// line colours (canvas cannot read CSS vars); text uses the darker --sr-rx-text/--sr-tx-text
const RX = '#409eff' // 下行：蓝
const TX = '#67c23a' // 上行：绿
const iface = ref('')
const names = ref([])
const rates = shallowRef({}) // name -> {rx, tx, rxTotal, txTotal, drop}
const series = ref({}) // name -> [[t, rx, tx]]
let prev = null
let timer = null

async function sample() {
  const d = await api.get('/api/traffic', undefined, { silent: true }).catch(() => null)
  if (!d) return
  names.value = Object.keys(d.dev).filter((n) => n !== 'lo')
  if (!iface.value) iface.value = names.value.find((n) => n.startsWith('ppp')) || names.value[0] || ''
  if (prev) {
    const dt = d.time - prev.time || 1
    const r = {}
    for (const n of names.value) {
      const a = d.dev[n]
      const b = prev.dev[n] || a
      // counters can reset (e.g. ppp reconnect): clamp to 0
      r[n] = { rx: Math.max(0, (a.rx_bytes - b.rx_bytes) / dt), tx: Math.max(0, (a.tx_bytes - b.tx_bytes) / dt),
        rxTotal: a.rx_bytes, txTotal: a.tx_bytes, drop: a.rx_drop }
      const s = (series.value[n] ||= [])
      s.push([d.time * 1000, r[n].rx, r[n].tx])
      if (s.length > MAX) s.shift()
    }
    rates.value = r
  }
  prev = d
}

const cur = computed(() => rates.value[iface.value] || { rx: 0, tx: 0 })
const peak = computed(() => {
  void rates.value
  const s = series.value[iface.value] || []
  return { rx: Math.max(0, ...s.map((p) => p[1])), tx: Math.max(0, ...s.map((p) => p[2])) }
})
const table = computed(() => names.value.map((name) => ({ name, ...(rates.value[name] || {}) })))

// fill between curve and the 0 axis (origin 'auto'), darker next to the curve
const area = (c, down = false) => ({ color: { type: 'linear', x: 0, y: down ? 1 : 0, x2: 0, y2: down ? 0 : 1,
  colorStops: [{ offset: 0, color: c + '55' }, { offset: 1, color: c + '08' }] } })

// round the half-range up to 1/2/5 x 10^n in the same 1024-based unit fmtBytes prints,
// so the axis ends on a tick (no duplicate edge label) and labels read 500 KB/s, 1 MB/s ...
function niceMax(v) {
  const unit = 1024 ** Math.max(0, Math.floor(Math.log(v) / Math.log(1024)))
  const x = v / unit
  const e = 10 ** Math.floor(Math.log10(x))
  const f = x / e
  // keep the half-step (interval = m/2) a whole number too: 2 -> 1, 10 -> 5
  return (f <= 2 ? 2 : f <= 4 ? 4 : f <= 10 ? 10 : 20) * e * unit
}
// y < 0 is upload: label it "↑", y > 0 download "↓", 0 plain
// phones drop "/s" (unit is in the legend context) to keep the axis narrow
const yLabel = (v) => (v === 0 ? '0'
  : `${v > 0 ? '↓' : '↑'}${isMobile.value ? '' : ' '}${fmtBytes(Math.abs(v), isMobile.value ? '' : '/s')}`)

const option = computed(() => {
  const s = series.value[iface.value] || []
  void rates.value // re-render on every sample
  // symmetric axis so 0 sits in the middle and both directions keep the same scale
  const RXN = t('traffic.rxLegend'), TXN = t('traffic.txLegend')
  const m = niceMax(Math.max(1000, peak.value.rx, peak.value.tx) * 1.05)
  return {
    color: [RX, TX],
    tooltip: {
      trigger: 'axis',
      formatter: (ps) => [new Date(ps[0].value[0]).toLocaleTimeString(),
        ...ps.map((p) => `${p.marker}${p.seriesName} ${fmtBytes(Math.abs(p.value[1]), '/s')}`)].join('<br>'),
    },
    legend: { data: [RXN, TXN], top: 0 },
    grid: { left: isMobile.value ? 0 : 8, right: isMobile.value ? 8 : 16, top: 36, bottom: 8, containLabel: true },
    xAxis: { type: 'time', splitLine: { show: false }, axisLabel: { hideOverlap: true, fontSize: isMobile.value ? 10 : 12 } },
    yAxis: {
      type: 'value', min: -m, max: m, interval: m / 2,
      axisLabel: { formatter: yLabel, fontSize: isMobile.value ? 10 : 12, margin: isMobile.value ? 4 : 8 },
      splitLine: { lineStyle: { type: 'dashed', opacity: 0.5 } },
    },
    series: [
      { name: RXN, type: 'line', showSymbol: false, smooth: 0.3, lineStyle: { width: 2 },
        areaStyle: area(RX), data: s.map((p) => [p[0], p[1]]),
        markLine: { silent: true, symbol: 'none', label: { show: false },
          lineStyle: { color: '#909399', type: 'solid', width: 1 }, data: [{ yAxis: 0 }] } },
      { name: TXN, type: 'line', showSymbol: false, smooth: 0.3, lineStyle: { width: 2 },
        areaStyle: area(TX, true), data: s.map((p) => [p[0], -p[2]]) },
    ],
  }
})

onMounted(() => {
  sample()
  timer = setInterval(sample, 2000)
})
onBeforeUnmount(() => clearInterval(timer))
</script>

<style scoped>
.stat-card { border-left: 4px solid transparent; }
.stat-card.rx { border-left-color: var(--sr-rx); }
.stat-card.tx { border-left-color: var(--sr-tx); }
.stat-card.rx .stat-value { color: var(--sr-rx-text); }
.stat-card.tx .stat-value { color: var(--sr-tx-text); }
.stat-sub { margin-top: 4px; color: var(--el-text-color-regular); font-size: 12px; }
</style>
