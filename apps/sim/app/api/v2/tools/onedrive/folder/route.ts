import { randomUUID } from 'crypto'
import { db } from '@sim/db'
import { account } from '@sim/db/schema'
import { eq } from 'drizzle-orm'
import { type NextRequest, NextResponse } from 'next/server'
import { getSession } from '@/lib/auth'
import { createLogger } from '@/lib/logs/console/logger'
import { validateMicrosoftGraphId } from '@/lib/security/input-validation'
import { refreshAccessTokenIfNeeded } from '@/app/api/auth/oauth/utils'

export const dynamic = 'force-dynamic'

const logger = createLogger('OneDriveFolderAPI')

export async function GET(request: NextRequest) {
  const requestId = randomUUID().slice(0, 8)

  try {
    const session = await getSession()
    if (!session?.user?.id) {
      return NextResponse.json({ error: 'User not authenticated' }, { status: 401 })
    }

    const { searchParams } = new URL(request.url)
    const credentialId = searchParams.get('credentialId')
    const fileId = searchParams.get('fileId')

    if (!credentialId || !fileId) {
      return NextResponse.json({ error: 'Credential ID and File ID are required' }, { status: 400 })
    }

    const fileIdValidation = validateMicrosoftGraphId(fileId, 'fileId')
    if (!fileIdValidation.isValid) {
      return NextResponse.json({ error: fileIdValidation.error }, { status: 400 })
    }

    const credentials = await db.select().from(account).where(eq(account.id, credentialId)).limit(1)
    if (!credentials.length) {
      return NextResponse.json({ error: 'Credential not found' }, { status: 404 })
    }

    const credential = credentials[0]
    if (credential.userId !== session.user.id) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 403 })
    }

    const accessToken = await refreshAccessTokenIfNeeded(credentialId, session.user.id, requestId)
    if (!accessToken) {
      return NextResponse.json({ error: 'Failed to obtain valid access token' }, { status: 401 })
    }

    const response = await fetch(
      `https://graph.microsoft.com/v1.0/me/drive/items/${fileId}?$select=id,name,folder,webUrl,createdDateTime,lastModifiedDateTime`,
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      }
    )

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({ error: { message: 'Unknown error' } }))
      return NextResponse.json(
        { error: errorData.error?.message || 'Failed to fetch folder from OneDrive' },
        { status: response.status }
      )
    }

    const folder = await response.json()

    const transformedFolder = {
      id: folder.id,
      name: folder.name,
      mimeType: 'application/vnd.microsoft.graph.folder',
      webViewLink: folder.webUrl,
      createdTime: folder.createdDateTime,
      modifiedTime: folder.lastModifiedDateTime,
    }

    return NextResponse.json({ file: transformedFolder }, { status: 200 })
  } catch (error) {
    logger.error(`[${requestId}] Error fetching folder from OneDrive`, error)
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 })
  }
}
