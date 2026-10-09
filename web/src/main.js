import { createApp } from 'vue'
import ElementPlus from 'element-plus'
import 'element-plus/dist/index.css'
import 'element-plus/theme-chalk/dark/css-vars.css'
import * as Icons from '@element-plus/icons-vue'
import App from './App.vue'
import router from './router'
import { i18n } from './i18n'
import './style.css'

const app = createApp(App)
for (const [name, comp] of Object.entries(Icons)) app.component(name, comp)
// Element Plus locale follows the UI language via <el-config-provider> in App.vue
app.use(ElementPlus).use(i18n).use(router).mount('#app')
