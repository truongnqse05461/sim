import { createLogger } from '@/lib/logs/console/logger'
import type { GoogleDriveToolParams, GoogleDriveUploadResponse } from '@/tools/google_drive/types'
import {
  GOOGLE_WORKSPACE_MIME_TYPES,
  handleSheetsFormat,
  SOURCE_MIME_TYPES,
} from '@/tools/google_drive/utils'
import type { ToolConfig } from '@/tools/types'

const logger = createLogger('GoogleDriveUploadTool')

export const uploadTool: ToolConfig<GoogleDriveToolParams, GoogleDriveUploadResponse> = {
  id: 'google_drive_upload',
  name: 'Upload to Google Drive',
  description: 'Upload a file to Google Drive',
  version: '1.0',

  oauth: {
    required: true,
    provider: 'google-drive',
    additionalScopes: ['https://www.googleapis.com/auth/drive.file'],
  },

  params: {
    accessToken: {
      type: 'string',
      required: true,
      visibility: 'hidden',
      description: 'The access token for the Google Drive API',
    },
    fileName: {
      type: 'string',
      required: true,
      visibility: 'user-or-llm',
      description: 'The name of the file to upload',
    },
    file: {
      type: 'file',
      required: false,
      visibility: 'user-only',
      description: 'Binary file to upload (UserFile object)',
    },
    content: {
      type: 'string',
      required: false,
      visibility: 'user-or-llm',
      description: 'Text content to upload (use this OR file, not both)',
    },
    mimeType: {
      type: 'string',
      required: false,
      visibility: 'hidden',
      description: 'The MIME type of the file to upload (auto-detected from file if not provided)',
    },
    folderSelector: {
      type: 'string',
      required: false,
      visibility: 'user-only',
      description: 'Select the folder to upload the file to',
    },
    folderId: {
      type: 'string',
      required: false,
      visibility: 'hidden',
      description: 'The ID of the folder to upload the file to (internal use)',
    },
  },

  request: {
    url: (params) => {
      // Use custom API route if file is provided, otherwise use Google Drive API directly
      if (params.file) {
        return '/api/tools/google_drive/upload'
      }
      return 'https://www.googleapis.com/drive/v3/files?supportsAllDrives=true'
    },
    method: 'POST',
    headers: (params) => {
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
      }
      // Google Drive API for text-only uploads needs Authorization
      if (!params.file) {
        headers.Authorization = `Bearer ${params.accessToken}`
      }
      return headers
    },
    body: (params) => {
      // Custom route handles file uploads
      if (params.file) {
        return {
          accessToken: params.accessToken,
          fileName: params.fileName,
          file: params.file,
          mimeType: params.mimeType,
          folderId: params.folderSelector || params.folderId,
        }
      }

      // Original text-only upload logic
      const metadata: {
        name: string | undefined
        mimeType: string
        parents?: string[]
      } = {
        name: params.fileName, // Important: Always include the filename in metadata
        mimeType: params.mimeType || 'text/plain',
      }

      // Add parent folder if specified (prefer folderSelector over folderId)
      const parentFolderId = params.folderSelector || params.folderId
      if (parentFolderId && parentFolderId.trim() !== '') {
        metadata.parents = [parentFolderId]
      }

      return metadata
    },
  },

  transformResponse: async (response: Response, params?: GoogleDriveToolParams) => {
    try {
      const data = await response.json()

      // Handle custom API route response (for file uploads)
      if (params?.file && data.success !== undefined) {
        if (!data.success) {
          logger.error('Failed to upload file via custom API route', {
            error: data.error,
          })
          throw new Error(data.error || 'Failed to upload file to Google Drive')
        }
        return {
          success: true,
          output: {
            file: data.output.file,
          },
        }
      }

      // Handle Google Drive API response (for text-only uploads)
      if (!response.ok) {
        logger.error('Failed to create file in Google Drive', {
          status: response.status,
          statusText: response.statusText,
          data,
        })
        throw new Error(data.error?.message || 'Failed to create file in Google Drive')
      }

      const fileId = data.id
      const requestedMimeType = params?.mimeType || 'text/plain'
      const authHeader =
        response.headers.get('Authorization') || `Bearer ${params?.accessToken || ''}`

      let preparedContent: string | undefined =
        typeof params?.content === 'string' ? (params?.content as string) : undefined

      if (requestedMimeType === 'application/vnd.google-apps.spreadsheet' && params?.content) {
        const { csv, rowCount, columnCount } = handleSheetsFormat(params.content as unknown)
        if (csv !== undefined) {
          preparedContent = csv
          logger.info('Prepared CSV content for Google Sheets upload', {
            fileId,
            fileName: params?.fileName,
            rowCount,
            columnCount,
          })
        }
      }

      const uploadMimeType = GOOGLE_WORKSPACE_MIME_TYPES.includes(requestedMimeType)
        ? SOURCE_MIME_TYPES[requestedMimeType] || 'text/plain'
        : requestedMimeType

      logger.info('Uploading content to file', {
        fileId,
        fileName: params?.fileName,
        requestedMimeType,
        uploadMimeType,
      })

      const uploadResponse = await fetch(
        `https://www.googleapis.com/upload/drive/v3/files/${fileId}?uploadType=media&supportsAllDrives=true`,
        {
          method: 'PATCH',
          headers: {
            Authorization: authHeader,
            'Content-Type': uploadMimeType,
          },
          body: preparedContent !== undefined ? preparedContent : params?.content || '',
        }
      )

      if (!uploadResponse.ok) {
        const uploadError = await uploadResponse.json()
        logger.error('Failed to upload content to file', {
          status: uploadResponse.status,
          statusText: uploadResponse.statusText,
          error: uploadError,
        })
        throw new Error(uploadError.error?.message || 'Failed to upload content to file')
      }

      if (GOOGLE_WORKSPACE_MIME_TYPES.includes(requestedMimeType)) {
        logger.info('Updating file name to ensure it persists after conversion', {
          fileId,
          fileName: params?.fileName,
        })

        const updateNameResponse = await fetch(
          `https://www.googleapis.com/drive/v3/files/${fileId}?supportsAllDrives=true`,
          {
            method: 'PATCH',
            headers: {
              Authorization: authHeader,
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({
              name: params?.fileName,
            }),
          }
        )

        if (!updateNameResponse.ok) {
          logger.warn('Failed to update filename after conversion, but content was uploaded', {
            status: updateNameResponse.status,
            statusText: updateNameResponse.statusText,
          })
        }
      }

      const finalFileResponse = await fetch(
        `https://www.googleapis.com/drive/v3/files/${fileId}?supportsAllDrives=true&fields=id,name,mimeType,webViewLink,webContentLink,size,createdTime,modifiedTime,parents`,
        {
          headers: {
            Authorization: authHeader,
          },
        }
      )

      const finalFile = await finalFileResponse.json()

      return {
        success: true,
        output: {
          file: {
            id: finalFile.id,
            name: finalFile.name,
            mimeType: finalFile.mimeType,
            webViewLink: finalFile.webViewLink,
            webContentLink: finalFile.webContentLink,
            size: finalFile.size,
            createdTime: finalFile.createdTime,
            modifiedTime: finalFile.modifiedTime,
            parents: finalFile.parents,
          },
        },
      }
    } catch (error: any) {
      logger.error('Error in upload transformation', {
        error: error.message,
        stack: error.stack,
      })
      throw error
    }
  },

  outputs: {
    file: { type: 'json', description: 'Uploaded file metadata including ID, name, and links' },
  },
}
