import { randomUUID } from 'crypto'
import { type NextRequest, NextResponse } from 'next/server'
import { z } from 'zod'
import { createLogger } from '@/lib/logs/console/logger'
import { createMySQLConnection, executeQuery, validateQuery } from '@/app/api/tools/mysql/utils'

const logger = createLogger('MySQLExecuteAPI')

const ExecuteSchema = z.object({
  host: z.string().min(1, 'Host is required'),
  port: z.coerce.number().int().positive('Port must be a positive integer'),
  database: z.string().min(1, 'Database name is required'),
  username: z.string().min(1, 'Username is required'),
  password: z.string().min(1, 'Password is required'),
  ssl: z.enum(['disabled', 'required', 'preferred']).default('preferred'),
  query: z.string().min(1, 'Query is required'),
})

export async function POST(request: NextRequest) {
  const requestId = randomUUID().slice(0, 8)

  try {
    const body = await request.json()
    const params = ExecuteSchema.parse(body)

    logger.info(
      `[${requestId}] Executing raw SQL on ${params.host}:${params.port}/${params.database}`
    )

    const validation = validateQuery(params.query)
    if (!validation.isValid) {
      logger.warn(`[${requestId}] Query validation failed: ${validation.error}`)
      return NextResponse.json(
        { error: `Query validation failed: ${validation.error}` },
        { status: 400 }
      )
    }

    const connection = await createMySQLConnection({
      host: params.host,
      port: params.port,
      database: params.database,
      username: params.username,
      password: params.password,
      ssl: params.ssl,
    })

    try {
      const result = await executeQuery(connection, params.query)

      logger.info(`[${requestId}] SQL executed successfully, ${result.rowCount} row(s) affected`)

      return NextResponse.json({
        message: `SQL executed successfully. ${result.rowCount} row(s) affected.`,
        rows: result.rows,
        rowCount: result.rowCount,
      })
    } finally {
      await connection.end()
    }
  } catch (error) {
    if (error instanceof z.ZodError) {
      logger.warn(`[${requestId}] Invalid request data`, { errors: error.errors })
      return NextResponse.json(
        { error: 'Invalid request data', details: error.errors },
        { status: 400 }
      )
    }

    const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred'
    logger.error(`[${requestId}] MySQL execute failed:`, error)

    return NextResponse.json({ error: `MySQL execute failed: ${errorMessage}` }, { status: 500 })
  }
}
