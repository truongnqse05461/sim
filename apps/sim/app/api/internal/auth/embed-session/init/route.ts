import crypto from 'crypto'
import { type NextRequest, NextResponse } from 'next/server'
import { env } from '@/lib/env'
import { createLogger } from '@/lib/logs/console/logger'
import { getRedisClient, hasProcessedMessage, markMessageAsProcessed } from '@/lib/redis'

const logger = createLogger('EmbedSessionInit')

// One-time code storage (fallback when Redis is not configured)
const inMemoryCodes = new Map<string, { value: string; expiry: number }>()
const CODE_PREFIX = 'embed-code:'
const NONCE_PREFIX = 'embed-nonce:'
const CODE_TTL_SECONDS = 120
const SIGNATURE_WINDOW_MS = 60_000

function generateCode(): string {
  return crypto.randomBytes(24).toString('hex')
}

async function storeCode(code: string, payload: any, ttlSeconds: number): Promise<void> {
  const redis = getRedisClient()
  const key = `${CODE_PREFIX}${code}`
  const value = JSON.stringify(payload)
  if (redis) {
    await redis.set(key, value, 'EX', ttlSeconds)
    return
  }
  inMemoryCodes.set(key, { value, expiry: Date.now() + ttlSeconds * 1000 })
}

async function consumeCode(code: string): Promise<any | null> {
  const redis = getRedisClient()
  const key = `${CODE_PREFIX}${code}`
  if (redis) {
    const value = await redis.get(key)
    if (!value) return null
    await redis.del(key)
    try {
      return JSON.parse(value)
    } catch {
      return null
    }
  }
  const entry = inMemoryCodes.get(key)
  if (!entry) return null
  inMemoryCodes.delete(key)
  if (entry.expiry < Date.now()) return null
  try {
    return JSON.parse(entry.value)
  } catch {
    return null
  }
}

function getRequestPath(req: NextRequest): string {
  try {
    const url = new URL(req.url)
    return url.pathname
  } catch {
    return '/api/internal/auth/embed-session/init'
  }
}

function computeSignature(
  secret: string,
  method: string,
  path: string,
  body: string,
  timestamp: string,
  nonce: string
): string {
  const payload = `${method}\n${path}\n${body}\n${timestamp}\n${nonce}`
  return crypto.createHmac('sha256', secret).update(payload).digest('hex')
}

async function verifySignedRequest(
  req: NextRequest,
  rawBody: string
): Promise<{ ok: boolean; error?: string }> {
  const signature = req.headers.get('x-internal-signature') || ''
  const timestamp = req.headers.get('x-internal-timestamp') || ''
  const nonce = req.headers.get('x-internal-nonce') || ''

  if (!signature || !timestamp || !nonce) {
    return { ok: false, error: 'Missing signature headers' }
  }

  const tsNum = Number(timestamp)
  if (!Number.isFinite(tsNum)) {
    return { ok: false, error: 'Invalid timestamp' }
  }
  const now = Date.now()
  if (Math.abs(now - tsNum) > SIGNATURE_WINDOW_MS) {
    return { ok: false, error: 'Stale request' }
  }

  // Replay protection via nonce single-use cache
  const nonceKey = `${NONCE_PREFIX}${nonce}`
  if (await hasProcessedMessage(nonceKey)) {
    return { ok: false, error: 'Replay detected' }
  }

  const method = req.method.toUpperCase()
  const path = getRequestPath(req)
  const expected = computeSignature(
    env.INTERNAL_API_SECRET,
    method,
    path,
    rawBody,
    timestamp,
    nonce
  )
  if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) {
    return { ok: false, error: 'Invalid signature' }
  }

  // Mark nonce as used for the window duration
  await markMessageAsProcessed(nonceKey, Math.ceil(SIGNATURE_WINDOW_MS / 1000))
  return { ok: true }
}

export async function POST(request: NextRequest) {
  try {
    const rawBody = await request.text()
    const verify = await verifySignedRequest(request, rawBody)
    if (!verify.ok) {
      return NextResponse.json({ error: verify.error || 'Unauthorized' }, { status: 401 })
    }

    // Parse once after signature verification
    let body: any = {}
    try {
      body = rawBody ? JSON.parse(rawBody) : {}
    } catch {
      return NextResponse.json({ error: 'Invalid JSON body' }, { status: 400 })
    }

    const { workspaceId, workflowId, redirectTo } = body || {}
    if (!workspaceId || !workflowId) {
      return NextResponse.json({ error: 'workspaceId and workflowId required' }, { status: 400 })
    }

    // Issue short-lived one-time code
    const code = generateCode()
    await storeCode(
      code,
      {
        workspaceId,
        workflowId,
        redirectTo: typeof redirectTo === 'string' ? redirectTo : undefined,
        iat: Date.now(),
        ttl: CODE_TTL_SECONDS,
      },
      CODE_TTL_SECONDS
    )

    logger.info('Issued embed one-time code')
    return NextResponse.json({ code, expiresIn: CODE_TTL_SECONDS })
  } catch (error: any) {
    logger.error('init error', { message: error?.message, stack: error?.stack })
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 })
  }
}

export const dynamic = 'force-dynamic'

// Export for consume route reuse
export const __consumeCode = consumeCode
export const __CODE_TTL_SECONDS = CODE_TTL_SECONDS
