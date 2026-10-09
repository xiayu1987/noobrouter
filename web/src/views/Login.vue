<template>
  <div class="login">
    <el-card class="card">
      <div class="head"><h2>{{ $t('login.title') }}</h2><lang-switch /></div>
      <p class="tip">{{ $t('login.tip') }}</p>
      <el-form @submit.prevent="submit">
        <el-form-item :label="$t('login.token')" label-position="top">
          <el-input v-model="value" type="password" show-password autocomplete="current-password" autofocus />
        </el-form-item>
        <el-button type="primary" native-type="submit" :loading="loading" class="w-full">{{ $t('login.submit') }}</el-button>
      </el-form>
    </el-card>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { api } from '../api'
import { token } from '../auth'
import { t } from '../i18n'
import LangSwitch from '../components/LangSwitch.vue'

const route = useRoute()
const router = useRouter()
const value = ref('')
const loading = ref(false)

async function submit() {
  if (!value.value.trim()) return
  loading.value = true
  token.set(value.value.trim())
  try {
    await api.get('/api/status', undefined, { silent: true })
    router.replace(route.query.redirect || '/')
  } catch (e) {
    token.clear()
    ElMessage.error(e.status === 401 ? t('login.bad') : e.message)
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.login { height: 100%; display: flex; align-items: center; justify-content: center; }
.card { width: min(360px, 92vw); }
.head { display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px; }
h2 { margin: 0; }
.tip { color: var(--el-text-color-secondary); font-size: 13px; }
</style>
