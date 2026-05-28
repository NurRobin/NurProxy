import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.tsx'
import { ThemeProvider } from './lib/theme'
import { ToastProvider } from './components/Toast'
import { HelpProvider } from './components/HelpPanel'
import { UIVariantProvider } from './lib/ui-variant'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <ThemeProvider>
      <ToastProvider>
        <UIVariantProvider>
          <HelpProvider>
            <App />
          </HelpProvider>
        </UIVariantProvider>
      </ToastProvider>
    </ThemeProvider>
  </StrictMode>,
)
