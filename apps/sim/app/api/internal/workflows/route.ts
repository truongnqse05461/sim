import { db } from '@sim/db'
import { workflow, workspace } from '@sim/db/schema'
import { eq } from 'drizzle-orm'
import { type NextRequest, NextResponse } from 'next/server'
import { z } from 'zod'
import { getSession } from '@/lib/auth'
import { createLogger } from '@/lib/logs/console/logger'
import { generateRequestId } from '@/lib/utils'
import { verifyWorkspaceMembership } from './utils'
import { getEmbedClaimsFromRequest } from '@/lib/auth/embed-request'
import { headers } from 'next/headers'
import { authenticateApiKeyFromHeader } from '@/lib/api-key/service'

const logger = createLogger('WorkflowAPI')

const CreateWorkflowSchema = z.object({
  name: z.string().min(1, 'Name is required'),
  description: z.string().optional().default(''),
  color: z.string().optional().default('#3972F6'),
  workspaceId: z.string().optional(),
  folderId: z.string().nullable().optional(),
})

// GET /api/workflows - Get workflows for user (optionally filtered by workspaceId)
export async function GET(request: Request) {
  const requestId = generateRequestId()
  const startTime = Date.now()
  const url = new URL(request.url)
  const workspaceId = url.searchParams.get('workspaceId')

  if (!workspaceId) {
    return NextResponse.json({ error: 'Workspace ID is required' }, { status: 400 })
  }

  try {
    const claims = await getEmbedClaimsFromRequest(request)
    if (!claims) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    }

    if (claims.workspaceId !== workspaceId) {
      return NextResponse.json({ error: 'Invalid workspace' }, { status: 401 })
    }

    const hdrs = await headers()
    const apiKeyHeader = hdrs.get('x-api-key') || hdrs.get('X-API-Key')
    if (!apiKeyHeader) {
      return NextResponse.json({ error: 'API key required' }, { status: 401 })
    }
    const auth = await authenticateApiKeyFromHeader(apiKeyHeader, {
      workspaceId: claims.workspaceId,
      keyTypes: ['workspace'],
    })
    if (!auth.success || !auth.userId || auth.workspaceId !== workspaceId) {
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
    }
    const userId = auth.userId

    if (workspaceId) {
      const workspaceExists = await db
        .select({ id: workspace.id })
        .from(workspace)
        .where(eq(workspace.id, workspaceId))
        .then((rows) => rows.length > 0)

      if (!workspaceExists) {
        logger.warn(
          `[${requestId}] Attempt to fetch workflows for non-existent workspace: ${workspaceId}`
        )
        return NextResponse.json(
          { error: 'Workspace not found', code: 'WORKSPACE_NOT_FOUND' },
          { status: 404 }
        )
      }

      const userRole = await verifyWorkspaceMembership(userId, workspaceId)

      if (!userRole) {
        logger.warn(
          `[${requestId}] User ${userId} attempted to access workspace ${workspaceId} without membership`
        )
        return NextResponse.json(
          { error: 'Access denied to this workspace', code: 'WORKSPACE_ACCESS_DENIED' },
          { status: 403 }
        )
      }
    }

    let workflows

    if (workspaceId) {
      workflows = await db.select().from(workflow).where(eq(workflow.workspaceId, workspaceId))
    } else {
      workflows = await db.select().from(workflow).where(eq(workflow.userId, userId))
    }

    return NextResponse.json({ data: workflows }, { status: 200 })
  } catch (error: any) {
    const elapsed = Date.now() - startTime
    logger.error(`[${requestId}] Workflow fetch error after ${elapsed}ms`, error)
    return NextResponse.json({ error: error.message }, { status: 500 })
  }
}

// POST /api/workflows - Create a new workflow
export async function POST(req: NextRequest) {
  const requestId = generateRequestId()

  const claims = await getEmbedClaimsFromRequest(req)
  if (!claims) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }
  
  const hdrs = await headers()
  const apiKeyHeader = hdrs.get('x-api-key') || hdrs.get('X-API-Key')
  if (!apiKeyHeader) {
    return NextResponse.json({ error: 'API key required' }, { status: 401 })
  }

  try {
    const body = await req.json()
    const { name, description, color, workspaceId, folderId } = CreateWorkflowSchema.parse(body)

    if (claims.workspaceId !== workspaceId) {
      return NextResponse.json({ error: 'Invalid workspace' }, { status: 401 })
    }

    const auth = await authenticateApiKeyFromHeader(apiKeyHeader, {
      workspaceId: claims.workspaceId,
      keyTypes: ['workspace'],
    })
    if (!auth.success || !auth.userId || auth.workspaceId !== workspaceId) {
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
    }

    const workflowId = crypto.randomUUID()
    const now = new Date()

    logger.info(`[${requestId}] Creating workflow ${workflowId} for user ${auth.userId}`)

    // Track workflow creation
    try {
      const { trackPlatformEvent } = await import('@/lib/telemetry/tracer')
      trackPlatformEvent('platform.workflow.created', {
        'workflow.id': workflowId,
        'workflow.name': name,
        'workflow.has_workspace': !!workspaceId,
        'workflow.has_folder': !!folderId,
      })
    } catch (_e) {
      // Silently fail
    }

    await db.insert(workflow).values({
      id: workflowId,
      userId: auth.userId,
      workspaceId: workspaceId || null,
      folderId: folderId || null,
      name,
      description,
      color,
      lastSynced: now,
      createdAt: now,
      updatedAt: now,
      isDeployed: false,
      collaborators: [],
      runCount: 0,
      variables: {},
      isPublished: false,
      marketplaceData: null,
    })

    logger.info(`[${requestId}] Successfully created empty workflow ${workflowId}`)

    return NextResponse.json({
      id: workflowId,
      name,
      description,
      color,
      workspaceId,
      folderId,
      createdAt: now,
      updatedAt: now,
    })
  } catch (error) {
    if (error instanceof z.ZodError) {
      logger.warn(`[${requestId}] Invalid workflow creation data`, {
        errors: error.errors,
      })
      return NextResponse.json(
        { error: 'Invalid request data', details: error.errors },
        { status: 400 }
      )
    }

    logger.error(`[${requestId}] Error creating workflow`, error)
    return NextResponse.json({ error: 'Failed to create workflow' }, { status: 500 })
  }
}
