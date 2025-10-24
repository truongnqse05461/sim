import { db } from '@sim/db'
import { workflow, workspace } from '@sim/db/schema'
import { eq } from 'drizzle-orm'
import { type NextRequest, NextResponse } from 'next/server'
import { z } from 'zod'
import { createLogger } from '@/lib/logs/console/logger'
import { generateRequestId } from '@/lib/utils'
import { getEmbedClaimsFromRequest } from '@/lib/auth/embed-request'
import { headers } from 'next/headers'
import { authenticateApiKeyFromHeader } from '@/lib/api-key/service'
import { saveWorkflowToNormalizedTables } from '@/lib/workflows/db-helpers'
import { getWorkflowAccessContext } from '@/lib/workflows/utils'
import { sanitizeAgentToolsInBlocks } from '@/lib/workflows/validation'
import { extractAndPersistCustomTools } from '@/lib/workflows/custom-tools-persistence'
import { WorkflowStateSchema } from '../[id]/state/route'

const logger = createLogger('WorkflowAPI')

const CreateWorkflowSchema = z.object({
  name: z.string().min(1, 'Name is required'),
  description: z.string().optional().default(''),
  color: z.string().optional().default('#3972F6'),
  workspaceId: z.string().optional(),
  folderId: z.string().nullable().optional(),
  template: WorkflowStateSchema
})

// POST /api/internal/workflows/create-with-template - Create a new workflow with pre-defined template
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
    const { name, description, color, workspaceId, folderId, template } = CreateWorkflowSchema.parse(body)

    if (!template) {
      return NextResponse.json({ error: 'Workflow template is required' }, { status: 400 })
    }

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

    // import template for workflow 
    await addingTemplate(requestId, workflowId, auth.userId, template)

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

async function addingTemplate(
    requestId: string,
    workflowId: string,
    userId: string,
    template: typeof WorkflowStateSchema
) {
    const startTime = Date.now()
    const state = WorkflowStateSchema.parse(template)

    if (!state) {
        return
    }

    // Fetch the workflow to check ownership/access
    const accessContext = await getWorkflowAccessContext(workflowId, userId)
    const workflowData = accessContext?.workflow

    if (!workflowData) {
        logger.warn(`[${requestId}] Workflow ${workflowId} not found for state update`)
        return NextResponse.json({ error: 'Workflow not found' }, { status: 404 })
    }

    // Check if user has permission to update this workflow
    const canUpdate =
        accessContext?.isOwner ||
        (workflowData.workspaceId
        ? accessContext?.workspacePermission === 'write' ||
            accessContext?.workspacePermission === 'admin'
        : false)

    if (!canUpdate) {
        logger.warn(
        `[${requestId}] User ${userId} denied permission to update workflow state ${workflowId}`
        )
        return NextResponse.json({ error: 'Access denied' }, { status: 403 })
    }

    // Sanitize custom tools in agent blocks before saving
    const { blocks: sanitizedBlocks, warnings } = sanitizeAgentToolsInBlocks(state.blocks as any)

    // Save to normalized tables
    // Ensure all required fields are present for WorkflowState type
    // Filter out blocks without type or name before saving
    const filteredBlocks = Object.entries(sanitizedBlocks).reduce(
        (acc, [blockId, block]: [string, any]) => {
        if (block.type && block.name) {
            // Ensure all required fields are present
            acc[blockId] = {
            ...block,
            enabled: block.enabled !== undefined ? block.enabled : true,
            horizontalHandles:
                block.horizontalHandles !== undefined ? block.horizontalHandles : true,
            isWide: block.isWide !== undefined ? block.isWide : false,
            height: block.height !== undefined ? block.height : 0,
            subBlocks: block.subBlocks || {},
            outputs: block.outputs || {},
            }
        }
        return acc
        },
        {} as typeof state.blocks
    )

    const workflowState = {
        blocks: filteredBlocks,
        edges: state.edges,
        loops: state.loops || {},
        parallels: state.parallels || {},
        lastSaved: state.lastSaved || Date.now(),
        isDeployed: state.isDeployed || false,
        deployedAt: state.deployedAt,
    }

    const saveResult = await saveWorkflowToNormalizedTables(workflowId, workflowState as any)

    if (!saveResult.success) {
        logger.error(`[${requestId}] Failed to save workflow ${workflowId} state:`, saveResult.error)
        return NextResponse.json(
        { error: 'Failed to save workflow state', details: saveResult.error },
        { status: 500 }
        )
    }

    // Extract and persist custom tools to database
    try {
        const { saved, errors } = await extractAndPersistCustomTools(workflowState, userId)

        if (saved > 0) {
        logger.info(`[${requestId}] Persisted ${saved} custom tool(s) to database`, { workflowId })
        }

        if (errors.length > 0) {
        logger.warn(`[${requestId}] Some custom tools failed to persist`, { errors, workflowId })
        }
    } catch (error) {
        logger.error(`[${requestId}] Failed to persist custom tools`, { error, workflowId })
    }

    // Update workflow's lastSynced timestamp
    await db
        .update(workflow)
        .set({
        lastSynced: new Date(),
        updatedAt: new Date(),
        })
        .where(eq(workflow.id, workflowId))

    const elapsed = Date.now() - startTime
    logger.info(`[${requestId}] Successfully saved workflow ${workflowId} state in ${elapsed}ms`)

    return
}