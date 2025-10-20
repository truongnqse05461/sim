import { PutObjectCommand } from '@aws-sdk/client-s3'
import { getSignedUrl } from '@aws-sdk/s3-request-presigner'
import { type NextRequest, NextResponse } from 'next/server'
import { v4 as uuidv4 } from 'uuid'
import { getSession } from '@/lib/auth'
import { createLogger } from '@/lib/logs/console/logger'
import { getStorageProvider, isUsingCloudStorage } from '@/lib/uploads'
import { isImageFileType } from '@/lib/uploads/file-utils'
// Dynamic imports for storage clients to avoid client-side bundling
import {
  BLOB_CHAT_CONFIG,
  BLOB_CONFIG,
  BLOB_COPILOT_CONFIG,
  BLOB_KB_CONFIG,
  BLOB_PROFILE_PICTURES_CONFIG,
  S3_CHAT_CONFIG,
  S3_CONFIG,
  S3_COPILOT_CONFIG,
  S3_KB_CONFIG,
  S3_PROFILE_PICTURES_CONFIG,
} from '@/lib/uploads/setup'
import { validateFileType } from '@/lib/uploads/validation'
import { createErrorResponse, createOptionsResponse } from '@/app/api/files/utils'

const logger = createLogger('PresignedUploadAPI')

interface PresignedUrlRequest {
  fileName: string
  contentType: string
  fileSize: number
  userId?: string
  chatId?: string
}

type UploadType = 'general' | 'knowledge-base' | 'chat' | 'copilot' | 'profile-pictures'

class PresignedUrlError extends Error {
  constructor(
    message: string,
    public code: string,
    public statusCode = 400
  ) {
    super(message)
    this.name = 'PresignedUrlError'
  }
}

class StorageConfigError extends PresignedUrlError {
  constructor(message: string) {
    super(message, 'STORAGE_CONFIG_ERROR', 500)
  }
}

class ValidationError extends PresignedUrlError {
  constructor(message: string) {
    super(message, 'VALIDATION_ERROR', 400)
  }
}

export async function POST(request: NextRequest) {
  try {
    const session = await getSession()
    if (!session?.user?.id) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    }

    let data: PresignedUrlRequest
    try {
      data = await request.json()
    } catch {
      throw new ValidationError('Invalid JSON in request body')
    }

    const { fileName, contentType, fileSize } = data

    if (!fileName?.trim()) {
      throw new ValidationError('fileName is required and cannot be empty')
    }
    if (!contentType?.trim()) {
      throw new ValidationError('contentType is required and cannot be empty')
    }
    if (!fileSize || fileSize <= 0) {
      throw new ValidationError('fileSize must be a positive number')
    }

    const MAX_FILE_SIZE = 100 * 1024 * 1024
    if (fileSize > MAX_FILE_SIZE) {
      throw new ValidationError(
        `File size (${fileSize} bytes) exceeds maximum allowed size (${MAX_FILE_SIZE} bytes)`
      )
    }

    const uploadTypeParam = request.nextUrl.searchParams.get('type')
    const uploadType: UploadType =
      uploadTypeParam === 'knowledge-base'
        ? 'knowledge-base'
        : uploadTypeParam === 'chat'
          ? 'chat'
          : uploadTypeParam === 'copilot'
            ? 'copilot'
            : uploadTypeParam === 'profile-pictures'
              ? 'profile-pictures'
              : 'general'

    if (uploadType === 'knowledge-base') {
      const fileValidationError = validateFileType(fileName, contentType)
      if (fileValidationError) {
        throw new ValidationError(`${fileValidationError.message}`)
      }
    }

    // Evaluate user id from session for copilot uploads
    const sessionUserId = session.user.id

    // Validate copilot-specific requirements (use session user)
    if (uploadType === 'copilot') {
      if (!sessionUserId?.trim()) {
        throw new ValidationError('Authenticated user session is required for copilot uploads')
      }
      // Only allow image uploads for copilot
      if (!isImageFileType(contentType)) {
        throw new ValidationError(
          'Only image files (JPEG, PNG, GIF, WebP, SVG) are allowed for copilot uploads'
        )
      }
    }

    // Validate profile picture requirements
    if (uploadType === 'profile-pictures') {
      if (!sessionUserId?.trim()) {
        throw new ValidationError(
          'Authenticated user session is required for profile picture uploads'
        )
      }
      // Only allow image uploads for profile pictures
      if (!isImageFileType(contentType)) {
        throw new ValidationError(
          'Only image files (JPEG, PNG, GIF, WebP, SVG) are allowed for profile picture uploads'
        )
      }
    }

    if (!isUsingCloudStorage()) {
      throw new StorageConfigError(
        'Direct uploads are only available when cloud storage is enabled'
      )
    }

    const storageProvider = getStorageProvider()
    logger.info(`Generating ${uploadType} presigned URL for ${fileName} using ${storageProvider}`)

    switch (storageProvider) {
      case 's3':
        return await handleS3PresignedUrl(
          fileName,
          contentType,
          fileSize,
          uploadType,
          sessionUserId
        )
      case 'blob':
        return await handleBlobPresignedUrl(
          fileName,
          contentType,
          fileSize,
          uploadType,
          sessionUserId
        )
      default:
        throw new StorageConfigError(`Unknown storage provider: ${storageProvider}`)
    }
  } catch (error) {
    logger.error('Error generating presigned URL:', error)

    if (error instanceof PresignedUrlError) {
      return NextResponse.json(
        {
          error: error.message,
          code: error.code,
          directUploadSupported: false,
        },
        { status: error.statusCode }
      )
    }

    return createErrorResponse(
      error instanceof Error ? error : new Error('Failed to generate presigned URL')
    )
  }
}

async function handleS3PresignedUrl(
  fileName: string,
  contentType: string,
  fileSize: number,
  uploadType: UploadType,
  userId?: string
) {
  try {
    const config =
      uploadType === 'knowledge-base'
        ? S3_KB_CONFIG
        : uploadType === 'chat'
          ? S3_CHAT_CONFIG
          : uploadType === 'copilot'
            ? S3_COPILOT_CONFIG
            : uploadType === 'profile-pictures'
              ? S3_PROFILE_PICTURES_CONFIG
              : S3_CONFIG

    if (!config.bucket || !config.region) {
      throw new StorageConfigError(`S3 configuration missing for ${uploadType} uploads`)
    }

    const safeFileName = fileName.replace(/\s+/g, '-').replace(/[^a-zA-Z0-9.-]/g, '_')

    let prefix = ''
    if (uploadType === 'knowledge-base') {
      prefix = 'kb/'
    } else if (uploadType === 'chat') {
      prefix = 'chat/'
    } else if (uploadType === 'copilot') {
      prefix = `${userId}/`
    } else if (uploadType === 'profile-pictures') {
      prefix = `${userId}/`
    }

    const uniqueKey = `${prefix}${uuidv4()}-${safeFileName}`

    const { sanitizeFilenameForMetadata } = await import('@/lib/uploads/s3/s3-client')
    const sanitizedOriginalName = sanitizeFilenameForMetadata(fileName)

    const metadata: Record<string, string> = {
      originalName: sanitizedOriginalName,
      uploadedAt: new Date().toISOString(),
    }

    if (uploadType === 'knowledge-base') {
      metadata.purpose = 'knowledge-base'
    } else if (uploadType === 'chat') {
      metadata.purpose = 'chat'
    } else if (uploadType === 'copilot') {
      metadata.purpose = 'copilot'
      metadata.userId = userId || ''
    } else if (uploadType === 'profile-pictures') {
      metadata.purpose = 'profile-pictures'
      metadata.userId = userId || ''
    }

    const command = new PutObjectCommand({
      Bucket: config.bucket,
      Key: uniqueKey,
      ContentType: contentType,
      Metadata: metadata,
    })

    let presignedUrl: string
    try {
      const { getS3Client } = await import('@/lib/uploads/s3/s3-client')
      presignedUrl = await getSignedUrl(getS3Client(), command, { expiresIn: 3600 })
    } catch (s3Error) {
      logger.error('Failed to generate S3 presigned URL:', s3Error)
      throw new StorageConfigError(
        'Failed to generate S3 presigned URL - check AWS credentials and permissions'
      )
    }

    const finalPath =
      uploadType === 'chat' || uploadType === 'profile-pictures'
        ? `https://${config.bucket}.s3.${config.region}.amazonaws.com/${uniqueKey}`
        : `/api/files/serve/s3/${encodeURIComponent(uniqueKey)}`

    logger.info(`Generated ${uploadType} S3 presigned URL for ${fileName} (${uniqueKey})`)
    logger.info(`Presigned URL: ${presignedUrl}`)
    logger.info(`Final path: ${finalPath}`)

    return NextResponse.json({
      presignedUrl,
      uploadUrl: presignedUrl, // Make sure we're returning the uploadUrl field
      fileInfo: {
        path: finalPath,
        key: uniqueKey,
        name: fileName,
        size: fileSize,
        type: contentType,
      },
      directUploadSupported: true,
    })
  } catch (error) {
    if (error instanceof PresignedUrlError) {
      throw error
    }
    logger.error('Error in S3 presigned URL generation:', error)
    throw new StorageConfigError('Failed to generate S3 presigned URL')
  }
}

async function handleBlobPresignedUrl(
  fileName: string,
  contentType: string,
  fileSize: number,
  uploadType: UploadType,
  userId?: string
) {
  try {
    const config =
      uploadType === 'knowledge-base'
        ? BLOB_KB_CONFIG
        : uploadType === 'chat'
          ? BLOB_CHAT_CONFIG
          : uploadType === 'copilot'
            ? BLOB_COPILOT_CONFIG
            : uploadType === 'profile-pictures'
              ? BLOB_PROFILE_PICTURES_CONFIG
              : BLOB_CONFIG

    if (
      !config.accountName ||
      !config.containerName ||
      (!config.accountKey && !config.connectionString)
    ) {
      throw new StorageConfigError(`Azure Blob configuration missing for ${uploadType} uploads`)
    }

    const safeFileName = fileName.replace(/\s+/g, '-').replace(/[^a-zA-Z0-9.-]/g, '_')

    let prefix = ''
    if (uploadType === 'knowledge-base') {
      prefix = 'kb/'
    } else if (uploadType === 'chat') {
      prefix = 'chat/'
    } else if (uploadType === 'copilot') {
      prefix = `${userId}/`
    } else if (uploadType === 'profile-pictures') {
      prefix = `${userId}/`
    }

    const uniqueKey = `${prefix}${uuidv4()}-${safeFileName}`

    const { getBlobServiceClient } = await import('@/lib/uploads/blob/blob-client')
    const blobServiceClient = getBlobServiceClient()
    const containerClient = blobServiceClient.getContainerClient(config.containerName)
    const blockBlobClient = containerClient.getBlockBlobClient(uniqueKey)

    const { BlobSASPermissions, generateBlobSASQueryParameters, StorageSharedKeyCredential } =
      await import('@azure/storage-blob')

    const sasOptions = {
      containerName: config.containerName,
      blobName: uniqueKey,
      permissions: BlobSASPermissions.parse('w'), // Write permission for upload
      startsOn: new Date(),
      expiresOn: new Date(Date.now() + 3600 * 1000), // 1 hour expiration
    }

    let sasToken: string
    try {
      sasToken = generateBlobSASQueryParameters(
        sasOptions,
        new StorageSharedKeyCredential(config.accountName, config.accountKey || '')
      ).toString()
    } catch (blobError) {
      logger.error('Failed to generate Azure Blob SAS token:', blobError)
      throw new StorageConfigError(
        'Failed to generate Azure Blob SAS token - check Azure credentials and permissions'
      )
    }

    const presignedUrl = `${blockBlobClient.url}?${sasToken}`

    // For chat images and profile pictures, use direct Blob URLs since they need to be permanently accessible
    // For other files, use serve path for access control
    const finalPath =
      uploadType === 'chat' || uploadType === 'profile-pictures'
        ? blockBlobClient.url
        : `/api/files/serve/blob/${encodeURIComponent(uniqueKey)}`

    logger.info(`Generated ${uploadType} Azure Blob presigned URL for ${fileName} (${uniqueKey})`)

    const uploadHeaders: Record<string, string> = {
      'x-ms-blob-type': 'BlockBlob',
      'x-ms-blob-content-type': contentType,
      'x-ms-meta-originalname': encodeURIComponent(fileName),
      'x-ms-meta-uploadedat': new Date().toISOString(),
    }

    if (uploadType === 'knowledge-base') {
      uploadHeaders['x-ms-meta-purpose'] = 'knowledge-base'
    } else if (uploadType === 'chat') {
      uploadHeaders['x-ms-meta-purpose'] = 'chat'
    } else if (uploadType === 'copilot') {
      uploadHeaders['x-ms-meta-purpose'] = 'copilot'
      uploadHeaders['x-ms-meta-userid'] = encodeURIComponent(userId || '')
    } else if (uploadType === 'profile-pictures') {
      uploadHeaders['x-ms-meta-purpose'] = 'profile-pictures'
      uploadHeaders['x-ms-meta-userid'] = encodeURIComponent(userId || '')
    }

    return NextResponse.json({
      presignedUrl,
      fileInfo: {
        path: finalPath,
        key: uniqueKey,
        name: fileName,
        size: fileSize,
        type: contentType,
      },
      directUploadSupported: true,
      uploadHeaders,
    })
  } catch (error) {
    if (error instanceof PresignedUrlError) {
      throw error
    }
    logger.error('Error in Azure Blob presigned URL generation:', error)
    throw new StorageConfigError('Failed to generate Azure Blob presigned URL')
  }
}

export async function OPTIONS() {
  return createOptionsResponse()
}
