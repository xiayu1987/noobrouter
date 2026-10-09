<template>
  <el-dropdown trigger="click" @command="setLocale">
    <el-button text :aria-label="$t('app.language')">
      <span class="lang">{{ current }}</span>
    </el-button>
    <template #dropdown>
      <el-dropdown-menu>
        <el-dropdown-item v-for="l in LANGS" :key="l.value" :command="l.value" :disabled="l.value === locale">
          {{ l.label }}
        </el-dropdown-item>
      </el-dropdown-menu>
    </template>
  </el-dropdown>
</template>

<script setup>
import { computed } from 'vue'
import { LANGS, locale, setLocale } from '../i18n'

// short label in the header: 中 / EN
const current = computed(() => (locale.value === 'en' ? 'EN' : '中'))
</script>

<style scoped>
.lang { font-weight: 600; min-width: 20px; display: inline-block; text-align: center; }
</style>
