// Single source of truth for the responsive breakpoint (keep in sync with style.css @media 768px)
import { ref } from 'vue'

const mq = typeof window !== 'undefined' ? window.matchMedia('(max-width: 768px)') : null
export const isMobile = ref(mq ? mq.matches : false)
mq?.addEventListener('change', (e) => { isMobile.value = e.matches })
