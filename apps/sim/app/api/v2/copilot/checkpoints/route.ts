import { db } from '@sim/db'
import { copilotChats, workflowCheckpoints } from '@sim/db/schema'
import { and, desc, eq } from 'drizzle-orm'
import { type NextRequest, NextResponse } from 'next/server'
import { z } from 'zod'
import {
  authenticateCopilotRequestSessionOnly,
  createBadRequestResponse,
  createInternalServerErrorResponse,
  createRequestTracker,
  createUnauthorizedResponse,
} from '@/lib/copilot/auth'
import { createLogger } from '@/lib/logs/console/logger'

const logger = createLogger('WorkflowCheckpointsAPI')

const CreateCheckpointSchema = z.object({
  workflowId: z.string(),
  chatId: z.string(),
  messageId: z.string().optional(), // ID of the user message that triggered this checkpoint
  workflowState: z.string(), // JSON stringified workflow state
})

/**
 * POST /api/copilot/checkpoints
 * Create a new checkpoint with JSON workflow state
 */
export async function POST(req: NextRequest) {
  const tracker = createRequestTracker()

  try {
    const { userId, isAuthenticated } = await authenticateCopilotRequestSessionOnly()
    if (!isAuthenticated || !userId) {
      return createUnauthorizedResponse()
    }

    const body = await req.json()
    const { workflowId, chatId, messageId, workflowState } = CreateCheckpointSchema.parse(body)

    logger.info(`[${tracker.requestId}] Creating workflow checkpoint`, {
      userId,
      workflowId,
      chatId,
      messageId,
      fullRequestBody: body,
      parsedData: { workflowId, chatId, messageId },
      messageIdType: typeof messageId,
      messageIdExists: !!messageId,
    })

    // Verify that the chat belongs to the user
    const [chat] = await db
      .select()
      .from(copilotChats)
      .where(and(eq(copilotChats.id, chatId), eq(copilotChats.userId, userId)))
      .limit(1)

    if (!chat) {
      return createBadRequestResponse('Chat not found or unauthorized')
    }

    // Parse the workflow state to validate it's valid JSON
    let parsedWorkflowState
    try {
      parsedWorkflowState = JSON.parse(workflowState)
    } catch (error) {
      return createBadRequestResponse('Invalid workflow state JSON')
    }

    // Create checkpoint with JSON workflow state
    const [checkpoint] = await db
      .insert(workflowCheckpoints)
      .values({
        userId,
        workflowId,
        chatId,
        messageId,
        workflowState: parsedWorkflowState, // Store as JSON object
      })
      .returning()

    logger.info(`[${tracker.requestId}] Workflow checkpoint created successfully`, {
      checkpointId: checkpoint.id,
      savedData: {
        checkpointId: checkpoint.id,
        userId: checkpoint.userId,
        workflowId: checkpoint.workflowId,
        chatId: checkpoint.chatId,
        messageId: checkpoint.messageId,
        createdAt: checkpoint.createdAt,
      },
    })

    return NextResponse.json({
      success: true,
      checkpoint: {
        id: checkpoint.id,
        userId: checkpoint.userId,
        workflowId: checkpoint.workflowId,
        chatId: checkpoint.chatId,
        messageId: checkpoint.messageId,
        createdAt: checkpoint.createdAt,
        updatedAt: checkpoint.updatedAt,
      },
    })
  } catch (error) {
    logger.error(`[${tracker.requestId}] Failed to create workflow checkpoint:`, error)
    return createInternalServerErrorResponse('Failed to create checkpoint')
  }
}

/**
 * GET /api/copilot/checkpoints?chatId=xxx
 * Retrieve workflow checkpoints for a chat
 */
export async function GET(req: NextRequest) {
  const tracker = createRequestTracker()

  try {
    const { userId, isAuthenticated } = await authenticateCopilotRequestSessionOnly()
    if (!isAuthenticated || !userId) {
      return createUnauthorizedResponse()
    }

    const { searchParams } = new URL(req.url)
    const chatId = searchParams.get('chatId')

    if (!chatId) {
      return createBadRequestResponse('chatId is required')
    }

    logger.info(`[${tracker.requestId}] Fetching workflow checkpoints for chat`, {
      userId,
      chatId,
    })

    // Fetch checkpoints for this user and chat
    const checkpoints = await db
      .select({
        id: workflowCheckpoints.id,
        userId: workflowCheckpoints.userId,
        workflowId: workflowCheckpoints.workflowId,
        chatId: workflowCheckpoints.chatId,
        messageId: workflowCheckpoints.messageId,
        createdAt: workflowCheckpoints.createdAt,
        updatedAt: workflowCheckpoints.updatedAt,
      })
      .from(workflowCheckpoints)
      .where(and(eq(workflowCheckpoints.chatId, chatId), eq(workflowCheckpoints.userId, userId)))
      .orderBy(desc(workflowCheckpoints.createdAt))

    logger.info(`[${tracker.requestId}] Retrieved ${checkpoints.length} workflow checkpoints`)

    return NextResponse.json({
      success: true,
      checkpoints,
    })
  } catch (error) {
    logger.error(`[${tracker.requestId}] Failed to fetch workflow checkpoints:`, error)
    return createInternalServerErrorResponse('Failed to fetch checkpoints')
  }
}
