export interface FileAttachment {
  id: string
  key: string
  filename: string
  media_type: string
  size: number
}

export interface MessageContent {
  type: 'text' | 'image' | 'document'
  text?: string
  source?: {
    type: 'base64'
    media_type: string
    data: string
  }
}

/**
 * Mapping of MIME types to content types
 */
export const MIME_TYPE_MAPPING: Record<string, 'image' | 'document'> = {
  // Images
  'image/jpeg': 'image',
  'image/jpg': 'image',
  'image/png': 'image',
  'image/gif': 'image',
  'image/webp': 'image',
  'image/svg+xml': 'image',

  // Documents
  'application/pdf': 'document',
  'text/plain': 'document',
  'text/csv': 'document',
  'application/json': 'document',
  'application/xml': 'document',
  'text/xml': 'document',
  'text/html': 'document',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document': 'document', // .docx
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': 'document', // .xlsx
  'application/vnd.openxmlformats-officedocument.presentationml.presentation': 'document', // .pptx
  'application/msword': 'document', // .doc
  'application/vnd.ms-excel': 'document', // .xls
  'application/vnd.ms-powerpoint': 'document', // .ppt
  'text/markdown': 'document',
  'application/rtf': 'document',
}

/**
 * Get the content type for a given MIME type
 */
export function getContentType(mimeType: string): 'image' | 'document' | null {
  return MIME_TYPE_MAPPING[mimeType.toLowerCase()] || null
}

/**
 * Check if a MIME type is supported
 */
export function isSupportedFileType(mimeType: string): boolean {
  return mimeType.toLowerCase() in MIME_TYPE_MAPPING
}

/**
 * Check if a MIME type is an image type (for copilot uploads)
 */
export function isImageFileType(mimeType: string): boolean {
  const imageTypes = [
    'image/jpeg',
    'image/jpg',
    'image/png',
    'image/gif',
    'image/webp',
    'image/svg+xml',
  ]
  return imageTypes.includes(mimeType.toLowerCase())
}

/**
 * Convert a file buffer to base64
 */
export function bufferToBase64(buffer: Buffer): string {
  return buffer.toString('base64')
}

/**
 * Create message content from file data
 */
export function createFileContent(fileBuffer: Buffer, mimeType: string): MessageContent | null {
  const contentType = getContentType(mimeType)
  if (!contentType) {
    return null
  }

  return {
    type: contentType,
    source: {
      type: 'base64',
      media_type: mimeType,
      data: bufferToBase64(fileBuffer),
    },
  }
}

/**
 * Extract file extension from filename
 */
export function getFileExtension(filename: string): string {
  const lastDot = filename.lastIndexOf('.')
  return lastDot !== -1 ? filename.slice(lastDot + 1).toLowerCase() : ''
}

/**
 * Get MIME type from file extension (fallback if not provided)
 */
export function getMimeTypeFromExtension(extension: string): string {
  const extensionMimeMap: Record<string, string> = {
    // Images
    jpg: 'image/jpeg',
    jpeg: 'image/jpeg',
    png: 'image/png',
    gif: 'image/gif',
    webp: 'image/webp',
    svg: 'image/svg+xml',

    // Documents
    pdf: 'application/pdf',
    txt: 'text/plain',
    csv: 'text/csv',
    json: 'application/json',
    xml: 'application/xml',
    html: 'text/html',
    htm: 'text/html',
    docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    pptx: 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    doc: 'application/msword',
    xls: 'application/vnd.ms-excel',
    ppt: 'application/vnd.ms-powerpoint',
    md: 'text/markdown',
    rtf: 'application/rtf',
  }

  return extensionMimeMap[extension.toLowerCase()] || 'application/octet-stream'
}

/**
 * Extract storage key from a file path
 * Handles various path formats: /api/files/serve/xyz, /api/files/serve/s3/xyz, etc.
 */
export function extractStorageKey(filePath: string): string {
  if (filePath.includes('/api/files/serve/s3/')) {
    return decodeURIComponent(filePath.split('/api/files/serve/s3/')[1])
  }
  if (filePath.includes('/api/files/serve/blob/')) {
    return decodeURIComponent(filePath.split('/api/files/serve/blob/')[1])
  }
  if (filePath.startsWith('/api/files/serve/')) {
    return decodeURIComponent(filePath.substring('/api/files/serve/'.length))
  }
  return filePath
}
