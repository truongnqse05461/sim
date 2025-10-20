import { type NextRequest, NextResponse } from 'next/server'
import { getSession } from '@/lib/auth'
import { authorizeCredentialUse } from '@/lib/auth/credential-access'
import { createLogger } from '@/lib/logs/console/logger'
import { generateRequestId } from '@/lib/utils'
import { refreshAccessTokenIfNeeded } from '@/app/api/auth/oauth/utils'
export const dynamic = 'force-dynamic'

const logger = createLogger('GoogleDriveFilesAPI')

function escapeForDriveQuery(value: string): string {
  return value.replace(/\\/g, '\\\\').replace(/'/g, "\\'")
}

export async function GET(request: NextRequest) {
  const requestId = generateRequestId()
  logger.info(`[${requestId}] Google Drive files request received`)

  try {
    const session = await getSession()

    if (!session?.user?.id) {
      logger.warn(`[${requestId}] Unauthenticated request rejected`)
      return NextResponse.json({ error: 'User not authenticated' }, { status: 401 })
    }

    const { searchParams } = new URL(request.url)
    const credentialId = searchParams.get('credentialId')
    const mimeType = searchParams.get('mimeType')
    const query = searchParams.get('query') || ''
    const folderId = searchParams.get('folderId') || searchParams.get('parentId') || ''
    const workflowId = searchParams.get('workflowId') || undefined

    if (!credentialId) {
      logger.warn(`[${requestId}] Missing credential ID`)
      return NextResponse.json({ error: 'Credential ID is required' }, { status: 400 })
    }

    const authz = await authorizeCredentialUse(request, { credentialId: credentialId!, workflowId })
    if (!authz.ok || !authz.credentialOwnerUserId) {
      logger.warn(`[${requestId}] Unauthorized credential access attempt`, authz)
      return NextResponse.json({ error: authz.error || 'Unauthorized' }, { status: 403 })
    }

    const accessToken = await refreshAccessTokenIfNeeded(
      credentialId!,
      authz.credentialOwnerUserId,
      requestId
    )

    if (!accessToken) {
      return NextResponse.json({ error: 'Failed to obtain valid access token' }, { status: 401 })
    }

    const qParts: string[] = ['trashed = false']
    if (folderId) {
      qParts.push(`'${escapeForDriveQuery(folderId)}' in parents`)
    }
    if (mimeType) {
      qParts.push(`mimeType = '${escapeForDriveQuery(mimeType)}'`)
    }
    if (query) {
      qParts.push(`name contains '${escapeForDriveQuery(query)}'`)
    }
    const q = encodeURIComponent(qParts.join(' and '))

    const response = await fetch(
      `https://www.googleapis.com/drive/v3/files?q=${q}&supportsAllDrives=true&includeItemsFromAllDrives=true&spaces=drive&fields=files(id,name,mimeType,iconLink,webViewLink,thumbnailLink,createdTime,modifiedTime,size,owners,parents)`,
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      }
    )

    if (!response.ok) {
      const error = await response.json().catch(() => ({ error: { message: 'Unknown error' } }))
      logger.error(`[${requestId}] Google Drive API error`, {
        status: response.status,
        error: error.error?.message || 'Failed to fetch files from Google Drive',
      })
      return NextResponse.json(
        {
          error: error.error?.message || 'Failed to fetch files from Google Drive',
        },
        { status: response.status }
      )
    }

    const data = await response.json()
    let files = data.files || []

    if (mimeType === 'application/vnd.google-apps.spreadsheet') {
      files = files.filter(
        (file: any) => file.mimeType === 'application/vnd.google-apps.spreadsheet'
      )
    } else if (mimeType === 'application/vnd.google-apps.document') {
      files = files.filter((file: any) => file.mimeType === 'application/vnd.google-apps.document')
    }

    return NextResponse.json({ files }, { status: 200 })
  } catch (error) {
    logger.error(`[${requestId}] Error fetching files from Google Drive`, error)
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 })
  }
}
