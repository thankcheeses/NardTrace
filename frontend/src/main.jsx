import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter, Route, Routes } from 'react-router-dom'
import './index.css'
import { CaseProvider } from './CaseContext'
import Layout from './components/Layout'
import Overview from './pages/Overview'
import EmailPage from './pages/EmailPage'
import IPPage from './pages/IPPage'
import DomainPage from './pages/DomainPage'
import UrlPage from './pages/UrlPage'
import FilePage from './pages/FilePage'
import CasesPage from './pages/CasesPage'
import CaseDetail from './pages/CaseDetail'

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <BrowserRouter>
      <CaseProvider>
        <Routes>
          <Route element={<Layout />}>
            <Route index element={<Overview />} />
            <Route path="email" element={<EmailPage />} />
            <Route path="ip" element={<IPPage />} />
            <Route path="domain" element={<DomainPage />} />
            <Route path="url" element={<UrlPage />} />
            <Route path="file" element={<FilePage />} />
            <Route path="cases" element={<CasesPage />} />
            <Route path="cases/:id" element={<CaseDetail />} />
          </Route>
        </Routes>
      </CaseProvider>
    </BrowserRouter>
  </React.StrictMode>,
)
