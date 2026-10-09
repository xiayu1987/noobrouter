<template>
  <div>
    <h3 class="page-title">{{ $t('menu.overview') }}</h3>
    <el-row :gutter="16" class="mb">
      <el-col v-for="c in cards" :key="c.label" :xs="12" :sm="8" :lg="4">
        <el-card shadow="never" class="mb">
          <div class="stat-label">{{ c.label }}</div>
          <div class="stat-value">{{ c.value }}</div>
          <el-progress v-if="c.pct !== undefined" :percentage="c.pct" :status="c.pct > 85 ? 'exception' : ''" :stroke-width="6" />
          <div v-else class="stat-label mt-xs">{{ c.sub }}</div>
        </el-card>
      </el-col>
    </el-row>
    <el-row :gutter="16">
      <el-col :md="12">
        <el-card shadow="never" :header="$t('overview.system')" class="mb">
          <el-descriptions :column="1" border size="small">
            <el-descriptions-item :label="$t('common.hostname')">{{ st.hostname }}</el-descriptions-item>
            <el-descriptions-item :label="$t('overview.kernel')">{{ st.kernel }}</el-descriptions-item>
            <el-descriptions-item :label="$t('overview.uptime')">{{ fmtUptime(st.uptime) }}</el-descriptions-item>
            <el-descriptions-item :label="$t('overview.load')">{{ (st.load || []).join(' / ') }}</el-descriptions-item>
            <el-descriptions-item :label="$t('overview.version')">{{ st.version }}</el-descriptions-item>
            <el-descriptions-item :label="$t('overview.mode')">
              <el-tag :type="st.dry_run ? 'warning' : 'success'">{{ st.dry_run ? $t('overview.dryRun') : $t('overview.writable') }}</el-tag>
            </el-descriptions-item>
          </el-descriptions>
        </el-card>
      </el-col>
      <el-col :md="12">
        <el-card shadow="never" header="WAN / LAN" class="mb">
          <el-descriptions :column="1" border size="small">
            <el-descriptions-item :label="$t('overview.wanIf')">
              {{ st.wan?.if }} <el-tag size="small" :type="st.wan?.up ? 'success' : 'danger'">{{ st.wan?.up ? 'UP' : 'DOWN' }}</el-tag>
            </el-descriptions-item>
            <el-descriptions-item label="IPv4">{{ (st.wan?.ipv4 || []).join(', ') || '-' }}</el-descriptions-item>
            <el-descriptions-item label="IPv6">
              <span class="mono">{{ (st.wan?.ipv6 || []).join(', ') || '-' }}</span>
            </el-descriptions-item>
            <el-descriptions-item :label="$t('overview.lanIf')">{{ st.lan_if }}</el-descriptions-item>
          </el-descriptions>
        </el-card>
      </el-col>
    </el-row>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { fmtBytes, fmtUptime, fmtUptimeShort } from '../api'
import { status as st } from '../status'
import { t } from '../i18n'

const pct = (a, b) => (b ? Math.round((100 * a) / b) : 0)
const cards = computed(() => [
  { label: 'CPU', value: `${st.cpu ?? '-'}%`, pct: Math.round(st.cpu || 0) },
  { label: t('overview.mem'), value: fmtBytes(st.mem?.used), pct: pct(st.mem?.used, st.mem?.total) },
  { label: t('overview.disk'), value: fmtBytes(st.disk?.used), pct: pct(st.disk?.used, st.disk?.total) },
  { label: t('overview.conns'), value: st.conntrack?.count ?? '-', pct: pct(st.conntrack?.count, st.conntrack?.max) },
  { label: t('overview.temp'), value: st.temp == null ? '-' : `${st.temp} °C`, sub: t('overview.tempSub') },
  { label: t('overview.uptime'), value: fmtUptimeShort(st.uptime), sub: fmtUptime(st.uptime) },
])
</script>
