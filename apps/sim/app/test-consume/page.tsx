'use client'

import { useCallback, useMemo, useState } from 'react'

export default function TestConsumePage() {
  const [workspaceId, setWorkspaceId] = useState('239ef995-97b3-4cfd-b803-89397c8fc51a')
  const [workflowId, setWorkflowId] = useState('2450922a-bb1e-4e2c-8b4e-0de7d91f5a7c')
  const [code, setCode] = useState('')
  const [iframeUrl, setIframeUrl] = useState<string>('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const canLoad = useMemo(() => {
    return Boolean(workspaceId && workflowId)
  }, [workspaceId, workflowId])

  const handleLoad = useCallback(async () => {
    setError(null)
    if (!canLoad) return
    setLoading(true)
    try {
      // Call consume endpoint if code is provided (optional)
      if (code) {
        const url = new URL('/api/internal/auth/embed-session/consume', window.location.origin)
        url.searchParams.set('code', code)
        const res = await fetch(url.toString(), { method: 'GET', credentials: 'include' })
        if (!res.ok) {
          const txt = await res.text()
          throw new Error(`Consume failed (${res.status}): ${txt}`)
        }
      }

      // Build iframe URL (same-origin to avoid frame-ancestors/SAMEORIGIN blocks)
      const target = `/workspace/${workspaceId}/w/${workflowId}`
      // const target = `/`;
      setIframeUrl(target)
    } catch (e: any) {
      setError(e?.message || 'Failed to load embed')
    } finally {
      setLoading(false)
    }
  }, [canLoad, code, workspaceId, workflowId])

  return (
    <div style={{ padding: 24, display: 'grid', gap: 16 }}>
      <h1>Embed Workflow Tester</h1>

      <label style={{ display: 'grid', gap: 4 }}>
        <span>Workspace ID</span>
        <input
          type='text'
          value={workspaceId}
          onChange={(e) => setWorkspaceId(e.target.value)}
          placeholder='0570c43b-...'
          style={{ padding: 8, border: '1px solid #ccc', borderRadius: 6 }}
        />
      </label>

      <label style={{ display: 'grid', gap: 4 }}>
        <span>Workflow ID</span>
        <input
          type='text'
          value={workflowId}
          onChange={(e) => setWorkflowId(e.target.value)}
          placeholder='8d781908-...'
          style={{ padding: 8, border: '1px solid #ccc', borderRadius: 6 }}
        />
      </label>

      <label style={{ display: 'grid', gap: 4 }}>
        <span>Code (from /embed-session/init)</span>
        <input
          type='text'
          value={code}
          onChange={(e) => setCode(e.target.value)}
          placeholder='paste code value'
          style={{ padding: 8, border: '1px solid #ccc', borderRadius: 6 }}
        />
      </label>

      <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
        <button onClick={handleLoad} disabled={!canLoad || loading}>
          {loading ? 'Loading...' : 'Load Embed'}
        </button>
        {error ? <span style={{ color: '#c00' }}>{error}</span> : null}
      </div>

      {iframeUrl ? (
        <div style={{ border: '1px solid #eee', borderRadius: 8, overflow: 'hidden', height: 600 }}>
          <iframe
            key={iframeUrl}
            src={iframeUrl}
            title='Workflow Embed'
            style={{ width: '100%', height: '100%', border: 0 }}
          />
        </div>
      ) : null}
    </div>
  )
}
