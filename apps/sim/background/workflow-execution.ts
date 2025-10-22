import { db } from '@sim/db'
import { workflow as workflowTable } from '@sim/db/schema'
import { task } from '@trigger.dev/sdk'
import { eq } from 'drizzle-orm'
import { v4 as uuidv4 } from 'uuid'
import { checkServerSideUsageLimits } from '@/lib/billing'
import { getPersonalAndWorkspaceEnv } from '@/lib/environment/utils'
import { createLogger } from '@/lib/logs/console/logger'
import { LoggingSession } from '@/lib/logs/execution/logging-session'
import { buildTraceSpans } from '@/lib/logs/execution/trace-spans/trace-spans'
import { decryptSecret } from '@/lib/utils'
import { loadDeployedWorkflowState } from '@/lib/workflows/db-helpers'
import { updateWorkflowRunCounts } from '@/lib/workflows/utils'
import { Executor } from '@/executor'
import { Serializer } from '@/serializer'
import { mergeSubblockState } from '@/stores/workflows/server-utils'

const logger = createLogger('TriggerWorkflowExecution')

export type WorkflowExecutionPayload = {
  workflowId: string
  userId: string
  input?: any
  triggerType?: 'api' | 'webhook' | 'schedule' | 'manual' | 'chat'
  metadata?: Record<string, any>
}

export async function executeWorkflowJob(payload: WorkflowExecutionPayload) {
  const workflowId = payload.workflowId
  const executionId = uuidv4()
  const requestId = executionId.slice(0, 8)

  logger.info(`[${requestId}] Starting workflow execution: ${workflowId}`, {
    userId: payload.userId,
    triggerType: payload.triggerType,
    executionId,
  })

  // Initialize logging session
  const triggerType = payload.triggerType || 'api'
  const loggingSession = new LoggingSession(workflowId, executionId, triggerType, requestId)

  try {
    const usageCheck = await checkServerSideUsageLimits(payload.userId)
    if (usageCheck.isExceeded) {
      logger.warn(
        `[${requestId}] User ${payload.userId} has exceeded usage limits. Skipping workflow execution.`,
        {
          currentUsage: usageCheck.currentUsage,
          limit: usageCheck.limit,
          workflowId: payload.workflowId,
        }
      )
      throw new Error(
        usageCheck.message ||
          'Usage limit exceeded. Please upgrade your plan to continue using workflows.'
      )
    }

    // Load workflow data from deployed state (this task is only used for API executions right now)
    const workflowData = await loadDeployedWorkflowState(workflowId)

    const { blocks, edges, loops, parallels } = workflowData

    // Merge subblock states (server-safe version doesn't need workflowId)
    const mergedStates = mergeSubblockState(blocks, {})

    // Process block states for execution
    const processedBlockStates = Object.entries(mergedStates).reduce(
      (acc, [blockId, blockState]) => {
        acc[blockId] = Object.entries(blockState.subBlocks).reduce(
          (subAcc, [key, subBlock]) => {
            subAcc[key] = subBlock.value
            return subAcc
          },
          {} as Record<string, any>
        )
        return acc
      },
      {} as Record<string, Record<string, any>>
    )

    // Get environment variables with workspace precedence
    const wfRows = await db
      .select({ workspaceId: workflowTable.workspaceId })
      .from(workflowTable)
      .where(eq(workflowTable.id, workflowId))
      .limit(1)
    const workspaceId = wfRows[0]?.workspaceId || undefined

    const { personalEncrypted, workspaceEncrypted } = await getPersonalAndWorkspaceEnv(
      payload.userId,
      workspaceId
    )
    const mergedEncrypted = { ...personalEncrypted, ...workspaceEncrypted }
    const decryptionPromises = Object.entries(mergedEncrypted).map(async ([key, encrypted]) => {
      const { decrypted } = await decryptSecret(encrypted)
      return [key, decrypted] as const
    })
    const decryptedPairs = await Promise.all(decryptionPromises)
    const decryptedEnvVars: Record<string, string> = Object.fromEntries(decryptedPairs)

    // Start logging session
    await loggingSession.safeStart({
      userId: payload.userId,
      workspaceId: workspaceId || '',
      variables: decryptedEnvVars,
    })

    // Create serialized workflow
    const serializer = new Serializer()
    const serializedWorkflow = serializer.serializeWorkflow(
      mergedStates,
      edges,
      loops || {},
      parallels || {},
      true // Enable validation during execution
    )

    // Create executor and execute
    const executor = new Executor({
      workflow: serializedWorkflow,
      currentBlockStates: processedBlockStates,
      envVarValues: decryptedEnvVars,
      workflowInput: payload.input || {},
      workflowVariables: {},
      contextExtensions: {
        executionId,
        workspaceId: workspaceId || '',
        isDeployedContext: true,
      },
    })

    // Set up logging on the executor
    loggingSession.setupExecutor(executor)

    const result = await executor.execute(workflowId)

    // Handle streaming vs regular result
    const executionResult = 'stream' in result && 'execution' in result ? result.execution : result

    logger.info(`[${requestId}] Workflow execution completed: ${workflowId}`, {
      success: executionResult.success,
      executionTime: executionResult.metadata?.duration,
      executionId,
    })

    // Update workflow run counts on success
    if (executionResult.success) {
      await updateWorkflowRunCounts(workflowId)
    }

    // Build trace spans and complete logging session (for both success and failure)
    const { traceSpans, totalDuration } = buildTraceSpans(executionResult)

    await loggingSession.safeComplete({
      endedAt: new Date().toISOString(),
      totalDurationMs: totalDuration || 0,
      finalOutput: executionResult.output || {},
      traceSpans: traceSpans as any,
    })

    return {
      success: executionResult.success,
      workflowId: payload.workflowId,
      executionId,
      output: executionResult.output,
      executedAt: new Date().toISOString(),
      metadata: payload.metadata,
    }
  } catch (error: any) {
    logger.error(`[${requestId}] Workflow execution failed: ${workflowId}`, {
      error: error.message,
      stack: error.stack,
    })

    const executionResult = error?.executionResult || { success: false, output: {}, logs: [] }
    const { traceSpans } = buildTraceSpans(executionResult)

    await loggingSession.safeCompleteWithError({
      endedAt: new Date().toISOString(),
      totalDurationMs: 0,
      error: {
        message: error.message || 'Workflow execution failed',
        stackTrace: error.stack,
      },
      traceSpans,
    })

    throw error
  }
}

export const workflowExecution = task({
  id: 'workflow-execution',
  retry: {
    maxAttempts: 1,
  },
  run: async (payload: WorkflowExecutionPayload) => executeWorkflowJob(payload),
})
