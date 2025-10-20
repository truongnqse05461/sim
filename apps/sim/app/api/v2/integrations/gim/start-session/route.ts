import { cookies, headers } from 'next/headers'
import { type NextRequest, NextResponse } from 'next/server'
import { authenticateApiKeyFromHeader, updateApiKeyLastUsed } from '@/lib/api-key/service'
import { embedCookie, signEmbedToken } from '@/lib/auth/embed'
import { createLogger } from '@/lib/logs/console/logger'

const logger = createLogger('StartSessionAPI')

export async function POST(request: NextRequest) {
  try {
    const hdrs = await headers()
    const apiKeyHeader = hdrs.get('x-api-key') || hdrs.get('X-API-Key')
    if (!apiKeyHeader) {
      return NextResponse.json({ error: 'API key required' }, { status: 401 })
    }

    const body = await request.json().catch(() => ({}) as any)
    const { workspaceId, workflowId, redirectTo } = body || {}
    if (!workspaceId) {
      return NextResponse.json({ error: 'workspaceId required' }, { status: 422 })
    }

    const auth = await authenticateApiKeyFromHeader(apiKeyHeader, {
      workspaceId,
      keyTypes: ['workspace'],
    })
    if (!auth.success || !auth.userId || auth.workspaceId !== workspaceId) {
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
    }

    // Optionally update last-used timestamp (best-effort)
    if (auth.keyId) updateApiKeyLastUsed(auth.keyId).catch(() => {})

    // TODO: verify workflowId belongs to workspaceId if provided (cheap check in DB)
    // For now we trust GIM to provide correct pairing; add DB check later.

    const token = await signEmbedToken({ workspaceId, workflowId, ttlSeconds: 15 * 60 })

    // Set as httpOnly cookie for the iframe; name kept separate from Better Auth cookie
    const cookieStore = await cookies()
    cookieStore.set(embedCookie.name, token, {
      httpOnly: true,
      secure: true,
      sameSite: 'lax',
      path: '/',
      maxAge: 15 * 60,
    })

    if (redirectTo) {
      try {
        const url = new URL(redirectTo)
        return NextResponse.redirect(url)
      } catch {
        logger.warn('Invalid redirectTo URL provided', { redirectTo })
      }
    }
    return new NextResponse(null, { status: 204 })
  } catch (error: any) {
    logger.error('start-session error', { error: error })
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 })
  }
}
