import React from 'react'
import ReactDOM from 'react-dom/client'
import { HashRouter, Route, Routes } from 'react-router-dom'
// Typefaces are bundled with the app (no font CDN), so opening it makes no third-party request.
import '@fontsource/inter/latin-400.css'
import '@fontsource/inter/latin-500.css'
import '@fontsource/inter/latin-600.css'
import '@fontsource/space-grotesk/latin-500.css'
import '@fontsource/space-grotesk/latin-600.css'
import '@fontsource/space-grotesk/latin-700.css'
import '@fontsource/jetbrains-mono/latin-400.css'
import '@fontsource/jetbrains-mono/latin-500.css'
import './index.css'
import { CaseProvider } from './CaseContext'
import Layout from './components/Layout'
import CaseDetail from './pages/CaseDetail'
import CasesPage from './pages/CasesPage'
import DomainPage from './pages/DomainPage'
import EmailPage from './pages/EmailPage'
import FilePage from './pages/FilePage'
import IPPage from './pages/IPPage'
import Overview from './pages/Overview'
import ReportPage from './pages/ReportPage'
import UrlPage from './pages/UrlPage'

// HashRouter so the app works from any static host (GitHub Pages) without server-side rewrites.
ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <HashRouter>
      <CaseProvider>
        <Routes>
          <Route path="cases/:id/report" element={<ReportPage />} />
          <Route element={<Layout />}>
            <Route index element={<Overview />} /><Route path="email" element={<EmailPage />} /><Route path="ip" element={<IPPage />} />
            <Route path="domain" element={<DomainPage />} /><Route path="url" element={<UrlPage />} /><Route path="file" element={<FilePage />} />
            <Route path="cases" element={<CasesPage />} /><Route path="cases/:id" element={<CaseDetail />} />
          </Route>
        </Routes>
      </CaseProvider>
    </HashRouter>
  </React.StrictMode>,
)
