import { db } from '@sim/db'
import { webhook, workflow } from '@sim/db/schema'
import { and, desc, eq } from 'drizzle-orm'
import { nanoid } from 'nanoid'
import { type NextRequest, NextResponse } from 'next/server'
import { getSession } from '@/lib/auth'
import { createLogger } from '@/lib/logs/console/logger'
import { getUserEntityPermissions } from '@/lib/permissions/utils'
import { getBaseUrl } from '@/lib/urls/utils'
import { generateRequestId } from '@/lib/utils'
import { getOAuthToken } from '@/app/api/auth/oauth/utils'

const logger = createLogger('WebhooksAPI')

export const dynamic = 'force-dynamic'

// Get all webhooks for the current user
export async function GET(request: NextRequest) {
  const requestId = generateRequestId()

  try {
    const session = await getSession()
    if (!session?.user?.id) {
      logger.warn(`[${requestId}] Unauthorized webhooks access attempt`)
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    }

    // Get query parameters
    const { searchParams } = new URL(request.url)
    const workflowId = searchParams.get('workflowId')
    const blockId = searchParams.get('blockId')

    if (workflowId && blockId) {
      // Collaborative-aware path: allow collaborators with read access to view webhooks
      // Fetch workflow to verify access
      const wf = await db
        .select({ id: workflow.id, userId: workflow.userId, workspaceId: workflow.workspaceId })
        .from(workflow)
        .where(eq(workflow.id, workflowId))
        .limit(1)

      if (!wf.length) {
        logger.warn(`[${requestId}] Workflow not found: ${workflowId}`)
        return NextResponse.json({ error: 'Workflow not found' }, { status: 404 })
      }

      const wfRecord = wf[0]
      let canRead = wfRecord.userId === session.user.id
      if (!canRead && wfRecord.workspaceId) {
        const permission = await getUserEntityPermissions(
          session.user.id,
          'workspace',
          wfRecord.workspaceId
        )
        canRead = permission === 'read' || permission === 'write' || permission === 'admin'
      }

      if (!canRead) {
        logger.warn(
          `[${requestId}] User ${session.user.id} denied permission to read webhooks for workflow ${workflowId}`
        )
        return NextResponse.json({ webhooks: [] }, { status: 200 })
      }

      const webhooks = await db
        .select({
          webhook: webhook,
          workflow: {
            id: workflow.id,
            name: workflow.name,
          },
        })
        .from(webhook)
        .innerJoin(workflow, eq(webhook.workflowId, workflow.id))
        .where(and(eq(webhook.workflowId, workflowId), eq(webhook.blockId, blockId)))
        .orderBy(desc(webhook.updatedAt))

      logger.info(
        `[${requestId}] Retrieved ${webhooks.length} webhooks for workflow ${workflowId} block ${blockId}`
      )
      return NextResponse.json({ webhooks }, { status: 200 })
    }

    if (workflowId && !blockId) {
      // For now, allow the call but return empty results to avoid breaking the UI
      return NextResponse.json({ webhooks: [] }, { status: 200 })
    }

    // Default: list webhooks owned by the session user
    logger.debug(`[${requestId}] Fetching user-owned webhooks for ${session.user.id}`)
    const webhooks = await db
      .select({
        webhook: webhook,
        workflow: {
          id: workflow.id,
          name: workflow.name,
        },
      })
      .from(webhook)
      .innerJoin(workflow, eq(webhook.workflowId, workflow.id))
      .where(eq(workflow.userId, session.user.id))

    logger.info(`[${requestId}] Retrieved ${webhooks.length} user-owned webhooks`)
    return NextResponse.json({ webhooks }, { status: 200 })
  } catch (error) {
    logger.error(`[${requestId}] Error fetching webhooks`, error)
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 })
  }
}

// Create or Update a webhook
export async function POST(request: NextRequest) {
  const requestId = generateRequestId()
  const userId = (await getSession())?.user?.id

  if (!userId) {
    logger.warn(`[${requestId}] Unauthorized webhook creation attempt`)
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }

  try {
    const body = await request.json()
    const { workflowId, path, provider, providerConfig, blockId } = body

    // Validate input
    if (!workflowId) {
      logger.warn(`[${requestId}] Missing required fields for webhook creation`, {
        hasWorkflowId: !!workflowId,
        hasPath: !!path,
      })
      return NextResponse.json({ error: 'Missing required fields' }, { status: 400 })
    }

    // Determine final path with special handling for credential-based providers
    // to avoid generating a new path on every save.
    let finalPath = path
    const credentialBasedProviders = ['gmail', 'outlook']
    const isCredentialBased = credentialBasedProviders.includes(provider)
    // Treat Microsoft Teams chat subscription as credential-based for path generation purposes
    const isMicrosoftTeamsChatSubscription =
      provider === 'microsoftteams' &&
      typeof providerConfig === 'object' &&
      providerConfig?.triggerId === 'microsoftteams_chat_subscription'

    // If path is missing
    if (!finalPath || finalPath.trim() === '') {
      if (isCredentialBased || isMicrosoftTeamsChatSubscription) {
        // Try to reuse existing path for this workflow+block if one exists
        if (blockId) {
          const existingForBlock = await db
            .select({ id: webhook.id, path: webhook.path })
            .from(webhook)
            .where(and(eq(webhook.workflowId, workflowId), eq(webhook.blockId, blockId)))
            .limit(1)

          if (existingForBlock.length > 0) {
            finalPath = existingForBlock[0].path
            logger.info(
              `[${requestId}] Reusing existing generated path for ${provider} trigger: ${finalPath}`
            )
          }
        }

        // If still no path, generate a new dummy path (first-time save)
        if (!finalPath || finalPath.trim() === '') {
          finalPath = `${provider}-${crypto.randomUUID()}`
          logger.info(`[${requestId}] Generated webhook path for ${provider} trigger: ${finalPath}`)
        }
      } else {
        logger.warn(`[${requestId}] Missing path for webhook creation`, {
          hasWorkflowId: !!workflowId,
          hasPath: !!path,
        })
        return NextResponse.json({ error: 'Missing required path' }, { status: 400 })
      }
    }

    // Check if the workflow exists and user has permission to modify it
    const workflowData = await db
      .select({
        id: workflow.id,
        userId: workflow.userId,
        workspaceId: workflow.workspaceId,
      })
      .from(workflow)
      .where(eq(workflow.id, workflowId))
      .limit(1)

    if (workflowData.length === 0) {
      logger.warn(`[${requestId}] Workflow not found: ${workflowId}`)
      return NextResponse.json({ error: 'Workflow not found' }, { status: 404 })
    }

    const workflowRecord = workflowData[0]

    // Check if user has permission to modify this workflow
    let canModify = false

    // Case 1: User owns the workflow
    if (workflowRecord.userId === userId) {
      canModify = true
    }

    // Case 2: Workflow belongs to a workspace and user has write or admin permission
    if (!canModify && workflowRecord.workspaceId) {
      const userPermission = await getUserEntityPermissions(
        userId,
        'workspace',
        workflowRecord.workspaceId
      )
      if (userPermission === 'write' || userPermission === 'admin') {
        canModify = true
      }
    }

    if (!canModify) {
      logger.warn(
        `[${requestId}] User ${userId} denied permission to modify webhook for workflow ${workflowId}`
      )
      return NextResponse.json({ error: 'Access denied' }, { status: 403 })
    }

    // Determine existing webhook to update (prefer by workflow+block for credential-based providers)
    let targetWebhookId: string | null = null
    if (isCredentialBased && blockId) {
      const existingForBlock = await db
        .select({ id: webhook.id })
        .from(webhook)
        .where(and(eq(webhook.workflowId, workflowId), eq(webhook.blockId, blockId)))
        .limit(1)
      if (existingForBlock.length > 0) {
        targetWebhookId = existingForBlock[0].id
      }
    }
    if (!targetWebhookId) {
      const existingByPath = await db
        .select({ id: webhook.id, workflowId: webhook.workflowId })
        .from(webhook)
        .where(eq(webhook.path, finalPath))
        .limit(1)
      if (existingByPath.length > 0) {
        // If a webhook with the same path exists but belongs to a different workflow, return an error
        if (existingByPath[0].workflowId !== workflowId) {
          logger.warn(`[${requestId}] Webhook path conflict: ${finalPath}`)
          return NextResponse.json(
            { error: 'Webhook path already exists.', code: 'PATH_EXISTS' },
            { status: 409 }
          )
        }
        targetWebhookId = existingByPath[0].id
      }
    }

    let savedWebhook: any = null // Variable to hold the result of save/update

    // Use the original provider config - Gmail/Outlook configuration functions will inject userId automatically
    const finalProviderConfig = providerConfig

    if (targetWebhookId) {
      logger.info(`[${requestId}] Updating existing webhook for path: ${finalPath}`, {
        webhookId: targetWebhookId,
        provider,
        hasCredentialId: !!(finalProviderConfig as any)?.credentialId,
        credentialId: (finalProviderConfig as any)?.credentialId,
      })
      const updatedResult = await db
        .update(webhook)
        .set({
          blockId,
          provider,
          providerConfig: finalProviderConfig,
          isActive: true,
          updatedAt: new Date(),
        })
        .where(eq(webhook.id, targetWebhookId))
        .returning()
      savedWebhook = updatedResult[0]
      logger.info(`[${requestId}] Webhook updated successfully`, {
        webhookId: savedWebhook.id,
        savedProviderConfig: savedWebhook.providerConfig,
      })
    } else {
      // Create a new webhook
      const webhookId = nanoid()
      logger.info(`[${requestId}] Creating new webhook with ID: ${webhookId}`)
      const newResult = await db
        .insert(webhook)
        .values({
          id: webhookId,
          workflowId,
          blockId,
          path: finalPath,
          provider,
          providerConfig: finalProviderConfig,
          isActive: true,
          createdAt: new Date(),
          updatedAt: new Date(),
        })
        .returning()
      savedWebhook = newResult[0]
    }

    // --- Attempt to create webhook in Airtable if provider is 'airtable' ---
    if (savedWebhook && provider === 'airtable') {
      logger.info(
        `[${requestId}] Airtable provider detected. Attempting to create webhook in Airtable.`
      )
      try {
        await createAirtableWebhookSubscription(request, userId, savedWebhook, requestId)
      } catch (err) {
        logger.error(`[${requestId}] Error creating Airtable webhook`, err)
        return NextResponse.json(
          {
            error: 'Failed to create webhook in Airtable',
            details: err instanceof Error ? err.message : 'Unknown error',
          },
          { status: 500 }
        )
      }
    }
    // --- End Airtable specific logic ---

    // --- Microsoft Teams subscription setup ---
    if (savedWebhook && provider === 'microsoftteams') {
      const { createTeamsSubscription } = await import('@/lib/webhooks/webhook-helpers')
      logger.info(`[${requestId}] Creating Teams subscription for webhook ${savedWebhook.id}`)

      const success = await createTeamsSubscription(
        request,
        savedWebhook,
        workflowRecord,
        requestId
      )

      if (!success) {
        return NextResponse.json(
          {
            error: 'Failed to create Teams subscription',
            details: 'Could not create subscription with Microsoft Graph API',
          },
          { status: 500 }
        )
      }
    }
    // --- End Teams subscription setup ---

    // --- Telegram webhook setup ---
    if (savedWebhook && provider === 'telegram') {
      const { createTelegramWebhook } = await import('@/lib/webhooks/webhook-helpers')
      logger.info(`[${requestId}] Creating Telegram webhook for webhook ${savedWebhook.id}`)

      const success = await createTelegramWebhook(request, savedWebhook, requestId)

      if (!success) {
        return NextResponse.json(
          {
            error: 'Failed to create Telegram webhook',
          },
          { status: 500 }
        )
      }
    }
    // --- End Telegram webhook setup ---

    // --- Gmail webhook setup ---
    if (savedWebhook && provider === 'gmail') {
      logger.info(`[${requestId}] Gmail provider detected. Setting up Gmail webhook configuration.`)
      try {
        const { configureGmailPolling } = await import('@/lib/webhooks/utils')
        const success = await configureGmailPolling(savedWebhook, requestId)

        if (!success) {
          logger.error(`[${requestId}] Failed to configure Gmail polling`)
          return NextResponse.json(
            {
              error: 'Failed to configure Gmail polling',
              details: 'Please check your Gmail account permissions and try again',
            },
            { status: 500 }
          )
        }

        logger.info(`[${requestId}] Successfully configured Gmail polling`)
      } catch (err) {
        logger.error(`[${requestId}] Error setting up Gmail webhook configuration`, err)
        return NextResponse.json(
          {
            error: 'Failed to configure Gmail webhook',
            details: err instanceof Error ? err.message : 'Unknown error',
          },
          { status: 500 }
        )
      }
    }
    // --- End Gmail specific logic ---

    // --- Outlook webhook setup ---
    if (savedWebhook && provider === 'outlook') {
      logger.info(
        `[${requestId}] Outlook provider detected. Setting up Outlook webhook configuration.`
      )
      try {
        const { configureOutlookPolling } = await import('@/lib/webhooks/utils')
        const success = await configureOutlookPolling(savedWebhook, requestId)

        if (!success) {
          logger.error(`[${requestId}] Failed to configure Outlook polling`)
          return NextResponse.json(
            {
              error: 'Failed to configure Outlook polling',
              details: 'Please check your Outlook account permissions and try again',
            },
            { status: 500 }
          )
        }

        logger.info(`[${requestId}] Successfully configured Outlook polling`)
      } catch (err) {
        logger.error(`[${requestId}] Error setting up Outlook webhook configuration`, err)
        return NextResponse.json(
          {
            error: 'Failed to configure Outlook webhook',
            details: err instanceof Error ? err.message : 'Unknown error',
          },
          { status: 500 }
        )
      }
    }
    // --- End Outlook specific logic ---

    const status = targetWebhookId ? 200 : 201
    return NextResponse.json({ webhook: savedWebhook }, { status })
  } catch (error: any) {
    logger.error(`[${requestId}] Error creating/updating webhook`, {
      message: error.message,
      stack: error.stack,
    })
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 })
  }
}

// Helper function to create the webhook subscription in Airtable
async function createAirtableWebhookSubscription(
  request: NextRequest,
  userId: string,
  webhookData: any,
  requestId: string
) {
  try {
    const { path, providerConfig } = webhookData
    const { baseId, tableId, includeCellValuesInFieldIds } = providerConfig || {}

    if (!baseId || !tableId) {
      logger.warn(`[${requestId}] Missing baseId or tableId for Airtable webhook creation.`, {
        webhookId: webhookData.id,
      })
      return // Cannot proceed without base/table IDs
    }

    const accessToken = await getOAuthToken(userId, 'airtable')
    if (!accessToken) {
      logger.warn(
        `[${requestId}] Could not retrieve Airtable access token for user ${userId}. Cannot create webhook in Airtable.`
      )
      throw new Error(
        'Airtable account connection required. Please connect your Airtable account in the trigger configuration and try again.'
      )
    }

    const notificationUrl = `${getBaseUrl()}/api/webhooks/trigger/${path}`

    const airtableApiUrl = `https://api.airtable.com/v0/bases/${baseId}/webhooks`

    const specification: any = {
      options: {
        filters: {
          dataTypes: ['tableData'], // Watch table data changes
          recordChangeScope: tableId, // Watch only the specified table
        },
      },
    }

    // Conditionally add the 'includes' field based on the config
    if (includeCellValuesInFieldIds === 'all') {
      specification.options.includes = {
        includeCellValuesInFieldIds: 'all',
      }
    }

    const requestBody: any = {
      notificationUrl: notificationUrl,
      specification: specification,
    }

    const airtableResponse = await fetch(airtableApiUrl, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(requestBody),
    })

    // Airtable often returns 200 OK even for errors in the body, check payload
    const responseBody = await airtableResponse.json()

    if (!airtableResponse.ok || responseBody.error) {
      const errorMessage =
        responseBody.error?.message || responseBody.error || 'Unknown Airtable API error'
      const errorType = responseBody.error?.type
      logger.error(
        `[${requestId}] Failed to create webhook in Airtable for webhook ${webhookData.id}. Status: ${airtableResponse.status}`,
        { type: errorType, message: errorMessage, response: responseBody }
      )
    } else {
      logger.info(
        `[${requestId}] Successfully created webhook in Airtable for webhook ${webhookData.id}.`,
        {
          airtableWebhookId: responseBody.id,
        }
      )
      // Store the airtableWebhookId (responseBody.id) within the providerConfig
      try {
        const currentConfig = (webhookData.providerConfig as Record<string, any>) || {}
        const updatedConfig = {
          ...currentConfig,
          externalId: responseBody.id, // Add/update the externalId
        }
        await db
          .update(webhook)
          .set({ providerConfig: updatedConfig, updatedAt: new Date() })
          .where(eq(webhook.id, webhookData.id))
      } catch (dbError: any) {
        logger.error(
          `[${requestId}] Failed to store externalId in providerConfig for webhook ${webhookData.id}.`,
          dbError
        )
        // Even if saving fails, the webhook exists in Airtable. Log and continue.
      }
    }
  } catch (error: any) {
    logger.error(
      `[${requestId}] Exception during Airtable webhook creation for webhook ${webhookData.id}.`,
      {
        message: error.message,
        stack: error.stack,
      }
    )
  }
}
