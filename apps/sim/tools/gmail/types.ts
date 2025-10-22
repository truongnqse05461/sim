import type { UserFile } from '@/executor/types'
import type { ToolResponse } from '@/tools/types'

// Base parameters shared by all operations
interface BaseGmailParams {
  accessToken: string
}

// Send operation parameters
export interface GmailSendParams extends BaseGmailParams {
  to: string
  cc?: string
  bcc?: string
  subject: string
  body: string
  attachments?: UserFile[]
}

// Read operation parameters
export interface GmailReadParams extends BaseGmailParams {
  messageId: string
  folder: string
  unreadOnly?: boolean
  maxResults?: number
  includeAttachments?: boolean
}

// Search operation parameters
export interface GmailSearchParams extends BaseGmailParams {
  query: string
  maxResults?: number
}

// Union type for all Gmail tool parameters
export type GmailToolParams = GmailSendParams | GmailReadParams | GmailSearchParams

// Response metadata
interface BaseGmailMetadata {
  id?: string
  threadId?: string
  labelIds?: string[]
}

interface EmailMetadata extends BaseGmailMetadata {
  from?: string
  to?: string
  subject?: string
  date?: string
  hasAttachments?: boolean
  attachmentCount?: number
}

interface SearchMetadata extends BaseGmailMetadata {
  results: Array<{
    id: string
    threadId: string
  }>
}

// Response format
export interface GmailToolResponse extends ToolResponse {
  output: {
    content: string
    metadata: EmailMetadata | SearchMetadata
    attachments?: GmailAttachment[]
  }
}

// Email Message Interface
export interface GmailMessage {
  id: string
  threadId: string
  labelIds: string[]
  snippet: string
  payload: {
    headers: Array<{
      name: string
      value: string
    }>
    body: {
      data?: string
      attachmentId?: string
      size?: number
    }
    parts?: Array<{
      mimeType: string
      filename?: string
      body: {
        data?: string
        attachmentId?: string
        size?: number
      }
      parts?: Array<any>
    }>
  }
}

// Gmail Attachment Interface (for processed attachments)
export interface GmailAttachment {
  name: string
  data: Buffer
  mimeType: string
  size: number
}
