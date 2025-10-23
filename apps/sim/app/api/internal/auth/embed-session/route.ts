import { type NextRequest, NextResponse } from 'next/server'
import { auth } from '@/lib/auth'
import { embedCookie, signEmbedToken } from '@/lib/auth/embed'
import { env } from '@/lib/env'
import { createLogger } from '@/lib/logs/console/logger'
import { getBaseUrl } from '@/lib/urls/utils'

const logger = createLogger('CreateEmbedSessionInternal')

export async function POST(request: NextRequest) {
  try {
    const secret = request.headers.get('x-internal-secret')
    if (!secret || secret !== env.INTERNAL_API_SECRET) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    }

    const body = await request.json().catch(() => ({}))
    const { redirectTo = '/', workspaceId, workflowId } = body || {}

    if (!workspaceId || !workflowId) {
      return NextResponse.json({ error: 'workspaceId and workflowId required' }, { status: 400 })
    }

    if (!env.SUPER_ADMIN_EMAIL || !env.SUPER_ADMIN_PASSWORD) {
      return NextResponse.json(
        { error: 'Super admin email and password required' },
        { status: 400 }
      )
    }

    const email = env.SUPER_ADMIN_EMAIL
    const password = env.SUPER_ADMIN_PASSWORD

    // Try sign up first
    let setCookieValue: string | null = null
    try {
      const { headers: signupHeaders } = await auth.api.signUpEmail({
        returnHeaders: true,
        body: {
          email,
          password,
          name: 'SIM',
        },
      })
      setCookieValue = signupHeaders?.get('set-cookie') || null
      logger.info('User signed up via internal endpoint', { email: env.SUPER_ADMIN_EMAIL })
    } catch (e: any) {
      // If user exists or sign-up fails, fall back to sign-in
      logger.warn('Sign up failed, attempting sign in', {
        email: env.SUPER_ADMIN_EMAIL,
        error: e?.message,
      })
      const { headers: signinHeaders } = await auth.api.signInEmail({
        returnHeaders: true,
        body: {
          email,
          password,
        },
      })
      setCookieValue = signinHeaders?.get('set-cookie') || null
      logger.info('User signed in via internal endpoint', { email })
    }

    // Build redirect response and forward Better Auth Set-Cookie
    let res = new NextResponse(null, { status: 204 })

    if (redirectTo) {
      try {
        const url = new URL(redirectTo, getBaseUrl())
        res = NextResponse.redirect(url)
      } catch {
        logger.warn('Invalid redirectTo URL provided', { redirectTo })
      }
    }

    if (setCookieValue) {
      res.headers.set('set-cookie', setCookieValue)
    }

    // generate embed token for iframe usage
    const token = await signEmbedToken({ workspaceId, workflowId, ttlSeconds: 24 * 60 * 60 })
    res.cookies.set(embedCookie.name, token, {
      httpOnly: true,
      // secure: true,
      sameSite: 'lax',
      path: '/',
      maxAge: 24 * 60 * 60,
    })

    return res
  } catch (error: any) {
    logger.error('create embed session error', { message: error?.message, stack: error?.stack })
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 })
  }
}

export const dynamic = 'force-dynamic'
