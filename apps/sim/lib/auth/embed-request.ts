import type { NextRequest } from 'next/server'
import { type EmbedClaims, embedCookie, verifyEmbedToken } from '@/lib/auth/embed'
import { getWorkflowById } from '@/lib/workflows/utils'

export async function getEmbedClaimsFromRequest(request: NextRequest): Promise<EmbedClaims | null> {
  const token = request.cookies.get(embedCookie.name)?.value
  if (!token) return null
  return await verifyEmbedToken(token)
}

export async function authenticateV2WorkflowAccess(
  request: NextRequest,
  workflowId: string
): Promise<{ allowed: boolean; reason?: string; embed?: EmbedClaims }> {
  const claims = await getEmbedClaimsFromRequest(request)
  if (!claims) {
    return { allowed: false, reason: 'No embed token' }
  }

  // If token is scoped to a specific workflowId, enforce exact match
  if (claims.workflowId) {
    if (claims.workflowId !== workflowId) {
      return { allowed: false, reason: 'Embed token workflow mismatch' }
    }
    return { allowed: true, embed: claims }
  }

  // Otherwise, ensure the requested workflow belongs to the embed workspace
  const wf = await getWorkflowById(workflowId)
  if (!wf) {
    return { allowed: false, reason: 'Workflow not found' }
  }

  if (wf.workspaceId && wf.workspaceId === claims.workspaceId) {
    return { allowed: true, embed: claims }
  }

  return { allowed: false, reason: 'Embed workspace mismatch' }
}
