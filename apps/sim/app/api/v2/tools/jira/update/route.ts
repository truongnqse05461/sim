import { NextResponse } from 'next/server'
import { createLogger } from '@/lib/logs/console/logger'
import { validateJiraCloudId, validateJiraIssueKey } from '@/lib/security/input-validation'
import { getJiraCloudId } from '@/tools/jira/utils'

export const dynamic = 'force-dynamic'

const logger = createLogger('JiraUpdateAPI')

export async function PUT(request: Request) {
  try {
    const {
      domain,
      accessToken,
      issueKey,
      summary,
      title,
      description,
      status,
      priority,
      assignee,
      cloudId: providedCloudId,
    } = await request.json()

    if (!domain) {
      logger.error('Missing domain in request')
      return NextResponse.json({ error: 'Domain is required' }, { status: 400 })
    }

    if (!accessToken) {
      logger.error('Missing access token in request')
      return NextResponse.json({ error: 'Access token is required' }, { status: 400 })
    }

    if (!issueKey) {
      logger.error('Missing issue key in request')
      return NextResponse.json({ error: 'Issue key is required' }, { status: 400 })
    }

    const cloudId = providedCloudId || (await getJiraCloudId(domain, accessToken))
    logger.info('Using cloud ID:', cloudId)

    const cloudIdValidation = validateJiraCloudId(cloudId, 'cloudId')
    if (!cloudIdValidation.isValid) {
      return NextResponse.json({ error: cloudIdValidation.error }, { status: 400 })
    }

    const issueKeyValidation = validateJiraIssueKey(issueKey, 'issueKey')
    if (!issueKeyValidation.isValid) {
      return NextResponse.json({ error: issueKeyValidation.error }, { status: 400 })
    }

    const url = `https://api.atlassian.com/ex/jira/${cloudId}/rest/api/3/issue/${issueKey}`

    logger.info('Updating Jira issue at:', url)

    const summaryValue = summary || title
    const fields: Record<string, any> = {}

    if (summaryValue) {
      fields.summary = summaryValue
    }

    if (description) {
      fields.description = {
        type: 'doc',
        version: 1,
        content: [
          {
            type: 'paragraph',
            content: [
              {
                type: 'text',
                text: description,
              },
            ],
          },
        ],
      }
    }

    if (status) {
      fields.status = {
        name: status,
      }
    }

    if (priority) {
      fields.priority = {
        name: priority,
      }
    }

    if (assignee) {
      fields.assignee = {
        id: assignee,
      }
    }

    const body = { fields }

    const response = await fetch(url, {
      method: 'PUT',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: 'application/json',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(body),
    })

    if (!response.ok) {
      const errorText = await response.text()
      logger.error('Jira API error:', {
        status: response.status,
        statusText: response.statusText,
        error: errorText,
      })

      return NextResponse.json(
        { error: `Jira API error: ${response.status} ${response.statusText}`, details: errorText },
        { status: response.status }
      )
    }

    const responseData = response.status === 204 ? {} : await response.json()
    logger.info('Successfully updated Jira issue:', issueKey)

    return NextResponse.json({
      success: true,
      output: {
        ts: new Date().toISOString(),
        issueKey: responseData.key || issueKey,
        summary: responseData.fields?.summary || 'Issue updated',
        success: true,
      },
    })
  } catch (error: any) {
    logger.error('Error updating Jira issue:', {
      error: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined,
    })

    return NextResponse.json(
      {
        error: error instanceof Error ? error.message : 'Internal server error',
        success: false,
      },
      { status: 500 }
    )
  }
}
