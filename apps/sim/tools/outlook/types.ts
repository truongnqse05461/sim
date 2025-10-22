import type { ToolResponse } from '@/tools/types'

export interface OutlookSendParams {
  accessToken: string
  to: string
  subject: string
  body: string
  // Thread support parameters
  replyToMessageId?: string
  conversationId?: string
  cc?: string
  bcc?: string
  attachments?: any[]
}

export interface OutlookSendResponse extends ToolResponse {
  output: {
    message: string
    results: any
  }
}

export interface OutlookReadParams {
  accessToken: string
  folder: string
  maxResults: number
  messageId?: string
  includeAttachments?: boolean
}

export interface OutlookReadResponse extends ToolResponse {
  output: {
    message: string
    results: CleanedOutlookMessage[]
  }
}

export interface OutlookDraftParams {
  accessToken: string
  to: string
  cc?: string
  bcc?: string
  subject: string
  body: string
  attachments?: any[]
}

export interface OutlookDraftResponse extends ToolResponse {
  output: {
    message: string
    results: any
  }
}

// Outlook API response interfaces
export interface OutlookEmailAddress {
  name?: string
  address: string
}

export interface OutlookRecipient {
  emailAddress: OutlookEmailAddress
}

export interface OutlookMessageBody {
  contentType?: string
  content?: string
}

export interface OutlookMessage {
  id: string
  subject?: string
  bodyPreview?: string
  body?: OutlookMessageBody
  sender?: OutlookRecipient
  from?: OutlookRecipient
  toRecipients?: OutlookRecipient[]
  ccRecipients?: OutlookRecipient[]
  bccRecipients?: OutlookRecipient[]
  receivedDateTime?: string
  sentDateTime?: string
  hasAttachments?: boolean
  isRead?: boolean
  importance?: string
  // Add other common fields
  '@odata.etag'?: string
  createdDateTime?: string
  lastModifiedDateTime?: string
  changeKey?: string
  categories?: string[]
  internetMessageId?: string
  parentFolderId?: string
  conversationId?: string
  conversationIndex?: string
  isDeliveryReceiptRequested?: boolean | null
  isReadReceiptRequested?: boolean
  isDraft?: boolean
  webLink?: string
  inferenceClassification?: string
  replyTo?: OutlookRecipient[]
}

export interface OutlookMessagesResponse {
  '@odata.context'?: string
  '@odata.nextLink'?: string
  value: OutlookMessage[]
}

// Outlook attachment interface (for tool responses)
export interface OutlookAttachment {
  name: string
  data: Buffer
  contentType: string
  size: number
}

// Cleaned message interface for our response
export interface CleanedOutlookMessage {
  id: string
  subject?: string
  bodyPreview?: string
  body?: {
    contentType?: string
    content?: string
  }
  sender?: {
    name?: string
    address?: string
  }
  from?: {
    name?: string
    address?: string
  }
  toRecipients: Array<{
    name?: string
    address?: string
  }>
  ccRecipients: Array<{
    name?: string
    address?: string
  }>
  receivedDateTime?: string
  sentDateTime?: string
  hasAttachments?: boolean
  attachments?: OutlookAttachment[] | any[]
  isRead?: boolean
  importance?: string
}

export type OutlookResponse = OutlookReadResponse | OutlookSendResponse | OutlookDraftResponse

export interface OutlookForwardParams {
  accessToken: string
  messageId: string
  to: string
  comment?: string
}

export interface OutlookForwardResponse extends ToolResponse {
  output: {
    message: string
    results: any
  }
}

export type OutlookExtendedResponse = OutlookResponse | OutlookForwardResponse
