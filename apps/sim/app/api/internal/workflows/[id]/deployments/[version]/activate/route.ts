import { db, workflow, workflowDeploymentVersion } from '@sim/db'
import { and, eq } from 'drizzle-orm'
import { NextRequest, NextResponse } from 'next/server'
import { createLogger } from '@/lib/logs/console/logger'
import { generateRequestId } from '@/lib/utils'
import { createErrorResponse, createSuccessResponse } from '@/app/api/workflows/utils'
import { headers } from 'next/headers'
import { authenticateV2WorkflowAccess } from '@/lib/auth/embed-request'
import { authenticateApiKeyFromHeader } from '@/lib/api-key/service'

const logger = createLogger('WorkflowActivateDeploymentAPI')

export const dynamic = 'force-dynamic'
export const runtime = 'nodejs'

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ id: string; version: string }> }
) {
  const requestId = generateRequestId()
  const { id, version } = await params

  const embedAuth = await authenticateV2WorkflowAccess(request, id)
  if (!embedAuth.allowed) {
    logger.warn(
      `[${requestId}] Unauthorized access attempt for workflow ${id} (no session, no API key, embed=${embedAuth.reason})`
    )
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }

  const claims = embedAuth.embed

  const hdrs = await headers()
  const apiKeyHeader = hdrs.get('x-api-key') || hdrs.get('X-API-Key')
  if (!apiKeyHeader) {
    return NextResponse.json({ error: 'API key required' }, { status: 401 })
  }
  const auth = await authenticateApiKeyFromHeader(apiKeyHeader, {
    workspaceId: claims.workspaceId,
    keyTypes: ['workspace'],
  })
  if (!auth.success || !auth.userId || auth.workspaceId !== claims.workspaceId) {
    return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
  }

  try {
    const versionNum = Number(version)
    if (!Number.isFinite(versionNum)) {
      return createErrorResponse('Invalid version', 400)
    }

    const now = new Date()

    await db.transaction(async (tx) => {
      await tx
        .update(workflowDeploymentVersion)
        .set({ isActive: false })
        .where(
          and(
            eq(workflowDeploymentVersion.workflowId, id),
            eq(workflowDeploymentVersion.isActive, true)
          )
        )

      const updated = await tx
        .update(workflowDeploymentVersion)
        .set({ isActive: true })
        .where(
          and(
            eq(workflowDeploymentVersion.workflowId, id),
            eq(workflowDeploymentVersion.version, versionNum)
          )
        )
        .returning({ id: workflowDeploymentVersion.id })

      if (updated.length === 0) {
        throw new Error('Deployment version not found')
      }

      await tx
        .update(workflow)
        .set({ isDeployed: true, deployedAt: now })
        .where(eq(workflow.id, id))
    })

    return createSuccessResponse({ success: true, deployedAt: now })
  } catch (error: any) {
    logger.error(`[${requestId}] Error activating deployment for workflow: ${id}`, error)
    return createErrorResponse(error.message || 'Failed to activate deployment', 500)
  }
}
