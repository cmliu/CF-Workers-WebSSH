const LANGUAGE_STORAGE_KEY = 'workers-webssh.language';

let language: 'zh-CN' | 'en' | null = null;
try {
  const stored = localStorage.getItem(LANGUAGE_STORAGE_KEY);
  if (stored === 'zh-CN' || stored === 'en') language = stored;
} catch {
  // The main module will use the browser language when storage is unavailable.
}

if (!language) language = navigator.language.toLowerCase().startsWith('zh') ? 'zh-CN' : 'en';
document.documentElement.lang = language;
document.documentElement.dataset.language = language;
