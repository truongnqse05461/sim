/**
 * Execution file management system for binary data transfer between blocks
 * This handles file storage, retrieval, and cleanup for workflow executions
 */

import type { UserFile } from '@/executor/types'

/**
 * Execution context for file operations
 */
export interface ExecutionContext {
  workspaceId: string
  workflowId: string
  executionId: string
}

/**
 * File metadata stored in execution logs - now just uses UserFile directly
 */
export type ExecutionFileMetadata = UserFile

/**
 * Generate execution-scoped storage key
 * Format: workspace_id/workflow_id/execution_id/filename
 */
export function generateExecutionFileKey(context: ExecutionContext, fileName: string): string {
  const { workspaceId, workflowId, executionId } = context
  const safeFileName = fileName.replace(/\s+/g, '-').replace(/[^a-zA-Z0-9.-]/g, '_')
  return `${workspaceId}/${workflowId}/${executionId}/${safeFileName}`
}

/**
 * Generate execution prefix for cleanup operations
 * Format: workspace_id/workflow_id/execution_id/
 */
export function generateExecutionPrefix(context: ExecutionContext): string {
  const { workspaceId, workflowId, executionId } = context
  return `${workspaceId}/${workflowId}/${executionId}/`
}

/**
 * Generate unique file ID for execution files
 */
export function generateFileId(): string {
  return `file_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`
}

/**
 * Check if a user file is expired
 */
export function isFileExpired(userFile: UserFile): boolean {
  return new Date(userFile.expiresAt) < new Date()
}

/**
 * Get file expiration date for execution files (5 minutes from now)
 */
export function getFileExpirationDate(): string {
  return new Date(Date.now() + 5 * 60 * 1000).toISOString()
}

/**
 * Check if a file is from execution storage based on its key pattern
 * Execution files have keys in format: workspaceId/workflowId/executionId/filename
 * Regular files have keys in format: timestamp-random-filename or just filename
 */
export function isExecutionFile(file: UserFile): boolean {
  if (!file.key) {
    return false
  }

  // Execution files have at least 3 slashes in their key (4 parts)
  // e.g., "workspace123/workflow456/execution789/document.pdf"
  const parts = file.key.split('/')
  return parts.length >= 4 && !file.key.startsWith('/api/') && !file.key.startsWith('http')
}
