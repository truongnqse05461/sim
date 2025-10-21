'use client'

import { useEffect } from 'react'

export default function TestLoginPage() {
  useEffect(() => {
    let cancelled = false
    const run = async () => {
      try {
        const res = await fetch('/api/internal/auth/embed-session', {
          method: 'POST',
          credentials: 'include',
          headers: {
            'content-type': 'application/json',
            'x-internal-secret': '79baf17f95effed90d8fca9681e7a04ebebbdee0ee52a7a98ac9576b60983142',
          },
          body: JSON.stringify({
            workspaceId: 'bab7894a-1ea8-4f96-8fb3-b0cc4533d112',
            workflowId: 'a59a2c8a-a45a-4af4-b395-1cb37da857aa',
            redirectTo:
              '/workspace/bab7894a-1ea8-4f96-8fb3-b0cc4533d112/w/a59a2c8a-a45a-4af4-b395-1cb37da857aa',
          }),
        })
        if (cancelled) return
        if (res.redirected) {
          window.location.href = res.url
          return
        }
        if (res.ok) {
          window.location.replace(
            '/workspace/bab7894a-1ea8-4f96-8fb3-b0cc4533d112/w/a59a2c8a-a45a-4af4-b395-1cb37da857aa'
          )
        }
      } catch {}
    }
    run()
    return () => {
      cancelled = true
    }
  }, [])

  return null
}
