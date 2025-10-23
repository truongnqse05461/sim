import { db } from '@sim/db'
import { permissions, workflow, workspace, apiKey } from '@sim/db/schema'
import { and, desc, eq, isNull } from 'drizzle-orm'
import { NextResponse } from 'next/server'
import { createLogger } from '@/lib/logs/console/logger'
import { headers } from 'next/headers'
import { authenticateApiKeyFromHeader } from '@/lib/api-key/service'
import { createApiKey } from '@/lib/api-key/auth'
import { nanoid } from 'nanoid'

const logger = createLogger('Workspaces')

// Get all workspaces for the current user
export async function GET() {
  const hdrs = await headers()
  const apiKeyHeader = hdrs.get('x-api-key') || hdrs.get('X-API-Key')
  if (!apiKeyHeader) {
    return NextResponse.json({ error: 'API key required' }, { status: 401 })
  }

  const auth = await authenticateApiKeyFromHeader(apiKeyHeader, {
    keyTypes: ['personal'],
  })
  if (!auth.success || !auth.userId) {
    return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
  }

  const userId = auth.userId

  // Get all workspaces where the user has permissions
  const userWorkspaces = await db
    .select({
      workspace: workspace,
      permissionType: permissions.permissionType,
    })
    .from(permissions)
    .innerJoin(workspace, eq(permissions.entityId, workspace.id))
    .where(and(eq(permissions.userId, userId), eq(permissions.entityType, 'workspace')))
    .orderBy(desc(workspace.createdAt))

  if (userWorkspaces.length === 0) {
    // Create a default workspace for the user
    const defaultWorkspace = await createDefaultWorkspace(userId, null)

    // Migrate existing workflows to the default workspace
    await migrateExistingWorkflows(userId, defaultWorkspace.id)

    return NextResponse.json({ workspaces: [defaultWorkspace] })
  }

  // If user has workspaces but might have orphaned workflows, migrate them
  await ensureWorkflowsHaveWorkspace(userId, userWorkspaces[0].workspace.id)

  // Format the response with permission information
  const workspacesWithPermissions = userWorkspaces.map(
    ({ workspace: workspaceDetails, permissionType }) => ({
      ...workspaceDetails,
      role: permissionType === 'admin' ? 'owner' : 'member', // Map admin to owner for compatibility
      permissions: permissionType,
    })
  )

  return NextResponse.json({ workspaces: workspacesWithPermissions })
}

// POST /api/workspaces - Create a new workspace
export async function POST(req: Request) {
  const hdrs = await headers()
  const apiKeyHeader = hdrs.get('x-api-key') || hdrs.get('X-API-Key')
  if (!apiKeyHeader) {
    return NextResponse.json({ error: 'API key required' }, { status: 401 })
  }
  
  const auth = await authenticateApiKeyFromHeader(apiKeyHeader, {
    keyTypes: ['personal'],
  })
  if (!auth.success || !auth.userId) {
    return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
  }

  const userId = auth.userId

  try {
    const { name, createAPIKeyIfNotExist } = await req.json()

    if (!name) {
      return NextResponse.json({ error: 'Name is required' }, { status: 400 })
    }

    const newWorkspace = await createWorkspace(userId, name)

    // Create a default API key for the workspace
    if (createAPIKeyIfNotExist) {
      const { key: plainKey, encryptedKey } = await createApiKey(true)

      if (!encryptedKey) {
        throw new Error('Failed to encrypt API key for storage')
      }

      const workspaceId = newWorkspace.id
      const apiKeyName = "workspace default API Key"

      const [newKey] = await db
        .insert(apiKey)
        .values({
          id: nanoid(),
          workspaceId,
          userId: userId,
          createdBy: userId,
          name: apiKeyName,
          key: encryptedKey,
          type: 'workspace',
          createdAt: new Date(),
          updatedAt: new Date(),
        })
        .returning({
          id: apiKey.id,
          name: apiKey.name,
          createdAt: apiKey.createdAt,
        })

      logger.info(`Created workspace API key: ${apiKeyName} in workspace ${workspaceId}`)

      return NextResponse.json({ 
        workspace: {
          ...newWorkspace,
          apiKey: plainKey,
        } 
      })
    }

    return NextResponse.json({ workspace: newWorkspace })
  } catch (error) {
    console.error('Error creating workspace:', error)
    return NextResponse.json({ error: 'Failed to create workspace' }, { status: 500 })
  }
}

// Helper function to create a default workspace
async function createDefaultWorkspace(userId: string, userName?: string | null) {
  const workspaceName = userName ? `${userName}'s Workspace` : 'My Workspace'
  return createWorkspace(userId, workspaceName)
}

// Helper function to create a workspace
async function createWorkspace(userId: string, name: string) {
  const workspaceId = crypto.randomUUID()
  const workflowId = crypto.randomUUID()
  const now = new Date()

  // Create the workspace and initial workflow in a transaction
  try {
    await db.transaction(async (tx) => {
      // Create the workspace
      await tx.insert(workspace).values({
        id: workspaceId,
        name,
        ownerId: userId,
        createdAt: now,
        updatedAt: now,
      })

      // Create admin permissions for the workspace owner
      await tx.insert(permissions).values({
        id: crypto.randomUUID(),
        entityType: 'workspace' as const,
        entityId: workspaceId,
        userId: userId,
        permissionType: 'admin' as const,
        createdAt: now,
        updatedAt: now,
      })
    })
  } catch (error) {
    logger.error(`Failed to create workspace ${workspaceId} with initial workflow:`, error)
    throw error
  }

  // Return the workspace data directly instead of querying again
  return {
    id: workspaceId,
    name,
    ownerId: userId,
    createdAt: now,
    updatedAt: now,
    role: 'owner',
  }
}

// Helper function to migrate existing workflows to a workspace
async function migrateExistingWorkflows(userId: string, workspaceId: string) {
  // Find all workflows that have no workspace ID
  const orphanedWorkflows = await db
    .select({ id: workflow.id })
    .from(workflow)
    .where(and(eq(workflow.userId, userId), isNull(workflow.workspaceId)))

  if (orphanedWorkflows.length === 0) {
    return // No orphaned workflows to migrate
  }

  logger.info(
    `Migrating ${orphanedWorkflows.length} workflows to workspace ${workspaceId} for user ${userId}`
  )

  // Bulk update all orphaned workflows at once
  await db
    .update(workflow)
    .set({
      workspaceId: workspaceId,
      updatedAt: new Date(),
    })
    .where(and(eq(workflow.userId, userId), isNull(workflow.workspaceId)))
}

// Helper function to ensure all workflows have a workspace
async function ensureWorkflowsHaveWorkspace(userId: string, defaultWorkspaceId: string) {
  // First check if there are any orphaned workflows
  const orphanedWorkflows = await db
    .select()
    .from(workflow)
    .where(and(eq(workflow.userId, userId), isNull(workflow.workspaceId)))

  if (orphanedWorkflows.length > 0) {
    // Directly update any workflows that don't have a workspace ID in a single query
    await db
      .update(workflow)
      .set({
        workspaceId: defaultWorkspaceId,
        updatedAt: new Date(),
      })
      .where(and(eq(workflow.userId, userId), isNull(workflow.workspaceId)))

    logger.info(`Fixed ${orphanedWorkflows.length} orphaned workflows for user ${userId}`)
  }
}
