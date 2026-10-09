<template>
  <el-dialog :model-value="!!modelValue" :title="title" class="sr-dialog-sm" @close="$emit('update:modelValue', null)">
    <el-form v-if="modelValue" ref="form" :model="row" :rules="rules" label-width="90px">
      <template v-if="modelValue.kind === 'forwards'">
        <el-form-item :label="$t('common.name')" prop="name"><el-input v-model="row.name" maxlength="60" /></el-form-item>
        <el-form-item :label="$t('common.proto')" prop="proto"><proto-select v-model="row.proto" /></el-form-item>
        <el-form-item :label="$t('rule.ext')" prop="ext"><el-input v-model="row.ext" :placeholder="$t('rule.extPh')" /></el-form-item>
        <el-form-item :label="$t('rule.lanIp')" prop="ip"><el-input v-model="row.ip" placeholder="192.168.50.x" /></el-form-item>
        <el-form-item :label="$t('rule.int')" prop="int"><el-input v-model="row.int" :placeholder="$t('rule.intPh')" /></el-form-item>
        <el-form-item :label="$t('common.enabled')"><el-switch v-model="row.enabled" /></el-form-item>
      </template>
      <template v-else>
        <el-form-item :label="$t('common.proto')" prop="proto"><proto-select v-model="row.proto" /></el-form-item>
        <el-form-item :label="$t('rule.port')" prop="port"><el-input v-model="row.port" :placeholder="$t('rule.portPh')" /></el-form-item>
        <el-form-item :label="$t('rule.iface')" prop="iface"><el-input v-model="row.iface" :placeholder="$t('rule.ifacePh')" /></el-form-item>
        <el-form-item :label="$t('rule.src')" prop="src"><el-input v-model="row.src" :placeholder="$t('rule.srcPh')" /></el-form-item>
        <el-form-item :label="$t('common.remark')" prop="comment"><el-input v-model="row.comment" maxlength="60" /></el-form-item>
      </template>
    </el-form>
    <template #footer>
      <el-button @click="$emit('update:modelValue', null)">{{ $t('common.cancel') }}</el-button>
      <el-button type="primary" @click="ok">{{ $t('common.confirm') }}</el-button>
    </template>
  </el-dialog>
</template>

<script setup>
import { computed, h, ref, watch } from 'vue'
import { ElOption, ElSelect } from 'element-plus'
import { t } from '../i18n'

const props = defineProps({ modelValue: { type: Object, default: null } })
const emit = defineEmits(['update:modelValue', 'done'])
const form = ref()
const row = ref({})
watch(() => props.modelValue, (v) => (row.value = v ? { ...v.row } : {}))

const title = computed(() => {
  const add = props.modelValue?.index < 0, fwd = props.modelValue?.kind === 'forwards'
  return t(`rule.${add ? 'add' : 'edit'}${fwd ? 'Fwd' : 'Open'}`)
})

// Client-side checks mirror the agent (which remains the authority).
const PORT = /^\d{1,5}([:-]\d{1,5})?$/
const portOk = (v) => PORT.test(v) && v.split(/[:-]/).every((x) => +x >= 1 && +x <= 65535)
const portRule = (optional) => ({
  validator: (_, v, cb) => (optional && !v) || portOk(String(v || '')) ? cb() : cb(new Error(t('rule.badPort'))),
  trigger: 'blur',
})
const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/
const IFNAME = /^[A-Za-z0-9_.-]{1,15}$/
const cidrOk = (v) => { const [ip, len, extra] = v.split('/'); return extra === undefined && IPV4.test(ip) && (len === undefined || (/^\d{1,2}$/.test(len) && +len <= 32)) }
const rules = {
  ext: [portRule(false)], port: [portRule(false)], int: [portRule(true)],
  ip: [{ validator: (_, v, cb) => (IPV4.test(v || '') ? cb() : cb(new Error(t('rule.badIp')))), trigger: 'blur' }],
  iface: [{ validator: (_, v, cb) => (!v || IFNAME.test(v) ? cb() : cb(new Error(t('rule.badIface')))), trigger: 'blur' }],
  src: [{ validator: (_, v, cb) => (!v || cidrOk(v) ? cb() : cb(new Error(t('rule.badSrc')))), trigger: 'blur' }],
}

const ProtoSelect = (p, { emit: e }) => h(ElSelect, { modelValue: p.modelValue, 'onUpdate:modelValue': (v) => e('update:modelValue', v) },
  () => [['tcp', 'TCP'], ['udp', 'UDP'], ['both', 'TCP+UDP']].map(([value, label]) => h(ElOption, { value, label })))
ProtoSelect.props = ['modelValue']
ProtoSelect.emits = ['update:modelValue']

async function ok() {
  await form.value.validate()
  const r = { ...row.value }
  if (props.modelValue.kind === 'forwards' && !r.int) r.int = r.ext
  emit('done', { kind: props.modelValue.kind, index: props.modelValue.index, row: r })
  emit('update:modelValue', null)
}
</script>
