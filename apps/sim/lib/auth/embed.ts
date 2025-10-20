import type { JWTPayload } from 'jose'
import { jwtVerify, SignJWT } from 'jose'
import { env } from '@/lib/env'

const EMBED_COOKIE_NAME = 'sim_embed'

export interface EmbedClaims {
  type: 'embed'
  workspaceId: string
  workflowId?: string
  iat: number
  exp: number
  aud: 'sim-embed'
  iss: 'sim'
}

function getSecret(): Uint8Array {
  // Reuse INTERNAL_API_SECRET for signing embed tokens
  return new TextEncoder().encode(env.INTERNAL_API_SECRET)
}

export async function signEmbedToken(params: {
  workspaceId: string
  workflowId?: string
  ttlSeconds?: number
}): Promise<string> {
  const now = Math.floor(Date.now() / 1000)
  const ttl = Math.max(60, Math.min(params.ttlSeconds ?? 15 * 60, 60 * 60)) // clamp 1m..60m
  const payload: EmbedClaims = {
    type: 'embed',
    workspaceId: params.workspaceId,
    workflowId: params.workflowId,
    iat: now,
    exp: now + ttl,
    aud: 'sim-embed',
    iss: 'sim',
  }

  return await new SignJWT(payload as unknown as JWTPayload)
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt(now)
    .setExpirationTime(payload.exp)
    .setAudience(payload.aud)
    .setIssuer(payload.iss)
    .sign(getSecret())
}

export async function verifyEmbedToken(token: string): Promise<EmbedClaims | null> {
  try {
    const { payload } = await jwtVerify(token, getSecret(), {
      audience: 'sim-embed',
      issuer: 'sim',
    })
    if (payload && payload.type === 'embed' && typeof payload.workspaceId === 'string') {
      return payload as unknown as EmbedClaims
    }
    return null
  } catch {
    return null
  }
}

export const embedCookie = {
  name: EMBED_COOKIE_NAME,
}
