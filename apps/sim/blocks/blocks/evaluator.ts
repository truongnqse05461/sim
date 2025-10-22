import { ChartBarIcon } from '@/components/icons'
import { isHosted } from '@/lib/environment'
import { createLogger } from '@/lib/logs/console/logger'
import type { BlockConfig, ParamType } from '@/blocks/types'
import type { ProviderId } from '@/providers/types'
import {
  getAllModelProviders,
  getHostedModels,
  getProviderIcon,
  providers,
} from '@/providers/utils'
import { useProvidersStore } from '@/stores/providers/store'
import type { ToolResponse } from '@/tools/types'

const logger = createLogger('EvaluatorBlock')

const getCurrentOllamaModels = () => {
  return useProvidersStore.getState().providers.ollama.models
}

interface Metric {
  name: string
  description: string
  range: {
    min: number
    max: number
  }
}

interface EvaluatorResponse extends ToolResponse {
  output: {
    content: string
    model: string
    tokens?: {
      prompt?: number
      completion?: number
      total?: number
    }
    cost?: {
      input: number
      output: number
      total: number
    }
    [metricName: string]: any // Allow dynamic metric fields
  }
}

export const generateEvaluatorPrompt = (metrics: Metric[], content: string): string => {
  // Filter out invalid/incomplete metrics first
  const validMetrics = metrics.filter((m) => m?.name && m.range)

  // Create a clear metrics description with name, range, and description
  const metricsDescription = validMetrics
    .map(
      (metric) =>
        `"${metric.name}" (${metric.range.min}-${metric.range.max}): ${metric.description || ''}` // Handle potentially missing description
    )
    .join('\n')

  // Format the content properly - try to detect and format JSON
  let formattedContent = content
  try {
    // If content looks like JSON (starts with { or [)
    if (
      typeof content === 'string' &&
      (content.trim().startsWith('{') || content.trim().startsWith('['))
    ) {
      // Try to parse and pretty-print
      const parsedContent = JSON.parse(content)
      formattedContent = JSON.stringify(parsedContent, null, 2)
    }
    // If it's already an object (shouldn't happen here but just in case)
    else if (typeof content === 'object') {
      formattedContent = JSON.stringify(content, null, 2)
    }
  } catch (e) {
    logger.warn('Warning: Content may not be valid JSON, using as-is', { e })
    formattedContent = content
  }

  // Generate an example of the expected output format using only valid metrics
  const exampleOutput = validMetrics.reduce(
    (acc, metric) => {
      // Ensure metric and name are valid before using them
      if (metric?.name) {
        acc[metric.name.toLowerCase()] = Math.floor((metric.range.min + metric.range.max) / 2) // Use middle of range as example
      } else {
        logger.warn('Skipping invalid metric during example generation:', metric)
      }
      return acc
    },
    {} as Record<string, number>
  )

  return `You are an objective evaluation agent. Analyze the content against the provided metrics and provide detailed scoring.

Evaluation Instructions:
- You MUST evaluate the content against each metric
- For each metric, provide a numeric score within the specified range
- Your response MUST be a valid JSON object with each metric name as a key and a numeric score as the value
- IMPORTANT: Use lowercase versions of the metric names as keys in your JSON response
- Follow the exact schema of the response format provided to you
- Do not include explanations in the JSON - only numeric scores
- Do not add any additional fields not specified in the schema
- Do not include ANY text before or after the JSON object

Metrics to evaluate:
${metricsDescription}

Content to evaluate:
${formattedContent}

Example of expected response format (with different scores):
${JSON.stringify(exampleOutput, null, 2)}

Remember: Your response MUST be a valid JSON object containing only the lowercase metric names as keys with their numeric scores as values. No text explanations.`
}

// Simplified response format generator that matches the agent block schema structure
const generateResponseFormat = (metrics: Metric[]) => {
  // Filter out invalid/incomplete metrics first
  const validMetrics = metrics.filter((m) => m?.name)

  // Create properties for each metric
  const properties: Record<string, any> = {}

  // Add each metric as a property
  validMetrics.forEach((metric) => {
    // We've already filtered, but double-check just in case
    if (metric?.name) {
      properties[metric.name.toLowerCase()] = {
        type: 'number',
        description: `${metric.description || ''} (Score between ${metric.range?.min ?? 0}-${metric.range?.max ?? 'N/A'})`, // Safely access range
      }
    } else {
      logger.warn('Skipping invalid metric during response format property generation:', metric)
    }
  })

  // Return a proper JSON Schema format
  return {
    name: 'evaluation_response',
    schema: {
      type: 'object',
      properties,
      // Use only valid, lowercase metric names for the required array
      required: validMetrics
        .filter((metric) => metric?.name)
        .map((metric) => metric.name.toLowerCase()),
      additionalProperties: false,
    },
    strict: true,
  }
}

export const EvaluatorBlock: BlockConfig<EvaluatorResponse> = {
  type: 'evaluator',
  name: 'Evaluator',
  description: 'Evaluate content',
  longDescription:
    'This is a core workflow block. Assess content quality using customizable evaluation metrics and scoring criteria. Create objective evaluation frameworks with numeric scoring to measure performance across multiple dimensions.',
  docsLink: 'https://docs.sim.ai/blocks/evaluator',
  category: 'tools',
  bgColor: '#4D5FFF',
  icon: ChartBarIcon,
  subBlocks: [
    {
      id: 'metrics',
      title: 'Evaluation Metrics',
      type: 'eval-input',
      layout: 'full',
      required: true,
    },
    {
      id: 'content',
      title: 'Content',
      type: 'short-input',
      layout: 'full',
      placeholder: 'Enter the content to evaluate',
      required: true,
    },
    {
      id: 'model',
      title: 'Model',
      type: 'combobox',
      layout: 'half',
      placeholder: 'Type or select a model...',
      required: true,
      options: () => {
        const providersState = useProvidersStore.getState()
        const baseModels = providersState.providers.base.models
        const ollamaModels = providersState.providers.ollama.models
        const openrouterModels = providersState.providers.openrouter.models
        const allModels = Array.from(new Set([...baseModels, ...ollamaModels, ...openrouterModels]))

        return allModels.map((model) => {
          const icon = getProviderIcon(model)
          return { label: model, id: model, ...(icon && { icon }) }
        })
      },
    },
    {
      id: 'apiKey',
      title: 'API Key',
      type: 'short-input',
      layout: 'full',
      placeholder: 'Enter your API key',
      password: true,
      connectionDroppable: false,
      required: true,
      condition: isHosted
        ? {
            field: 'model',
            value: getHostedModels(),
            not: true, // Show for all models EXCEPT those listed
          }
        : () => ({
            field: 'model',
            value: getCurrentOllamaModels(),
            not: true, // Show for all models EXCEPT Ollama models
          }),
    },
    {
      id: 'azureEndpoint',
      title: 'Azure OpenAI Endpoint',
      type: 'short-input',
      layout: 'full',
      password: true,
      placeholder: 'https://your-resource.openai.azure.com',
      connectionDroppable: false,
      condition: {
        field: 'model',
        value: providers['azure-openai'].models,
      },
    },
    {
      id: 'azureApiVersion',
      title: 'Azure API Version',
      type: 'short-input',
      layout: 'full',
      placeholder: '2024-07-01-preview',
      connectionDroppable: false,
      condition: {
        field: 'model',
        value: providers['azure-openai'].models,
      },
    },
    {
      id: 'temperature',
      title: 'Temperature',
      type: 'slider',
      layout: 'half',
      min: 0,
      max: 2,
      value: () => '0.1',
      hidden: true,
    },
    {
      id: 'systemPrompt',
      title: 'System Prompt',
      type: 'code',
      layout: 'full',
      hidden: true,
      value: (params: Record<string, any>) => {
        try {
          const metrics = params.metrics || []

          // Process content safely
          let processedContent = ''
          if (typeof params.content === 'object') {
            processedContent = JSON.stringify(params.content, null, 2)
          } else {
            processedContent = String(params.content || '')
          }

          // Generate prompt and response format directly
          const promptText = generateEvaluatorPrompt(metrics, processedContent)
          const responseFormatObj = generateResponseFormat(metrics)

          // Create a clean, simple JSON object
          const result = {
            systemPrompt: promptText,
            responseFormat: responseFormatObj,
          }

          return JSON.stringify(result)
        } catch (e) {
          logger.error('Error in systemPrompt value function:', { e })
          // Return a minimal valid JSON as fallback
          return JSON.stringify({
            systemPrompt: 'Evaluate the content and return a JSON with metric scores.',
            responseFormat: {
              schema: {
                type: 'object',
                properties: {},
                additionalProperties: true,
              },
            },
          })
        }
      },
    },
  ],
  tools: {
    access: [
      'openai_chat',
      'anthropic_chat',
      'google_chat',
      'xai_chat',
      'deepseek_chat',
      'deepseek_reasoner',
    ],
    config: {
      tool: (params: Record<string, any>) => {
        const model = params.model || 'gpt-4o'
        if (!model) {
          throw new Error('No model selected')
        }
        const tool = getAllModelProviders()[model as ProviderId]
        if (!tool) {
          throw new Error(`Invalid model selected: ${model}`)
        }
        return tool
      },
    },
  },
  inputs: {
    metrics: {
      type: 'json' as ParamType,
      description: 'Evaluation metrics configuration',
      schema: {
        type: 'array',
        properties: {},
        items: {
          type: 'object',
          properties: {
            name: {
              type: 'string',
              description: 'Name of the metric',
            },
            description: {
              type: 'string',
              description: 'Description of what this metric measures',
            },
            range: {
              type: 'object',
              properties: {
                min: {
                  type: 'number',
                  description: 'Minimum possible score',
                },
                max: {
                  type: 'number',
                  description: 'Maximum possible score',
                },
              },
              required: ['min', 'max'],
            },
          },
          required: ['name', 'description', 'range'],
        },
      },
    },
    model: { type: 'string' as ParamType, description: 'AI model to use' },
    apiKey: { type: 'string' as ParamType, description: 'Provider API key' },
    azureEndpoint: { type: 'string' as ParamType, description: 'Azure OpenAI endpoint URL' },
    azureApiVersion: { type: 'string' as ParamType, description: 'Azure API version' },
    temperature: {
      type: 'number' as ParamType,
      description: 'Response randomness level (low for consistent evaluation)',
    },
    content: { type: 'string' as ParamType, description: 'Content to evaluate' },
  },
  outputs: {
    content: { type: 'string', description: 'Evaluation results' },
    model: { type: 'string', description: 'Model used' },
    tokens: { type: 'json', description: 'Token usage' },
    cost: { type: 'json', description: 'Cost information' },
  } as any,
}
