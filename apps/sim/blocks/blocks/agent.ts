import { AgentIcon } from '@/components/icons'
import { isHosted } from '@/lib/environment'
import { createLogger } from '@/lib/logs/console/logger'
import type { BlockConfig } from '@/blocks/types'
import { AuthMode } from '@/blocks/types'
import {
  getAllModelProviders,
  getHostedModels,
  getMaxTemperature,
  getProviderIcon,
  MODELS_WITH_REASONING_EFFORT,
  MODELS_WITH_VERBOSITY,
  providers,
  supportsTemperature,
} from '@/providers/utils'

const getCurrentOllamaModels = () => {
  return useProvidersStore.getState().providers.ollama.models
}

import { useProvidersStore } from '@/stores/providers/store'
import type { ToolResponse } from '@/tools/types'

const logger = createLogger('AgentBlock')

interface AgentResponse extends ToolResponse {
  output: {
    content: string
    model: string
    tokens?: {
      prompt?: number
      completion?: number
      total?: number
    }
    toolCalls?: {
      list: Array<{
        name: string
        arguments: Record<string, any>
      }>
      count: number
    }
  }
}

// Helper function to get the tool ID from a block type
const getToolIdFromBlock = (blockType: string): string | undefined => {
  try {
    const { getAllBlocks } = require('@/blocks/registry')
    const blocks = getAllBlocks()
    const block = blocks.find(
      (b: { type: string; tools?: { access?: string[] } }) => b.type === blockType
    )
    return block?.tools?.access?.[0]
  } catch (error) {
    logger.error('Error getting tool ID from block', { error })
    return undefined
  }
}

export const AgentBlock: BlockConfig<AgentResponse> = {
  type: 'agent',
  name: 'Agent',
  description: 'Build an agent',
  authMode: AuthMode.ApiKey,
  longDescription:
    'The Agent block is a core workflow block that is a wrapper around an LLM. It takes in system/user prompts and calls an LLM provider. It can also make tool calls by directly containing tools inside of its tool input. It can additionally return structured output.',
  bestPractices: `
  - Cannot use core blocks like API, Webhook, Function, Workflow, Memory as tools. Only integrations or custom tools. 
  - Check custom tools examples for YAML syntax. Only construct these if there isn't an existing integration for that purpose.
  - Response Format should be a valid JSON Schema. This determines the output of the agent only if present. Fields can be accessed at root level by the following blocks: e.g. <agent1.field>. If response format is not present, the agent will return the standard outputs: content, model, tokens, toolCalls.
  `,
  docsLink: 'https://docs.sim.ai/blocks/agent',
  category: 'blocks',
  bgColor: 'var(--brand-primary-hex)',
  icon: AgentIcon,
  subBlocks: [
    {
      id: 'systemPrompt',
      title: 'System Prompt',
      type: 'long-input',
      layout: 'full',
      placeholder: 'Enter system prompt...',
      rows: 5,
      wandConfig: {
        enabled: true,
        maintainHistory: true, // Enable conversation history for iterative improvements
        prompt: `You are an expert system prompt engineer. Create a system prompt based on the user's request.

### CONTEXT
{context}

### INSTRUCTIONS
Write a system prompt following best practices. Match the complexity level the user requests.

### CORE PRINCIPLES
1. **Role Definition**: Start with "You are..." to establish identity and function
2. **Direct Commands**: Use action verbs like "Analyze", "Generate", "Classify"
3. **Be Specific**: Include output format, quality standards, behaviors, target audience
4. **Clear Boundaries**: Define focus areas and priorities
5. **Examples**: Add concrete examples when helpful

### STRUCTURE
- **Primary Role**: Clear identity statement
- **Core Capabilities**: Main functions and expertise
- **Behavioral Guidelines**: Task approach and interaction style
- **Output Requirements**: Format, style, quality expectations
- **Tool Integration**: Specific tool usage instructions

### TOOL INTEGRATION
When users mention tools, include explicit instructions:
- **Web Search**: "Use Exa to gather current information from authoritative sources"
- **Communication**: "Send messages via Slack/Discord/Teams with appropriate tone"
- **Email**: "Compose emails through Gmail with professional formatting"
- **Data**: "Query databases, analyze spreadsheets, call APIs as needed"

### EXAMPLES

**Simple**: "Create a customer service agent"
→ You are a professional customer service representative. Respond to inquiries about orders, returns, and products with empathy and efficiency. Maintain a helpful tone while providing accurate information and clear next steps.

**Detailed**: "Build a research assistant for market analysis"
→ You are an expert market research analyst specializing in competitive intelligence and industry trends. Conduct thorough market analysis using systematic methodologies.

Use Exa to gather information from industry sources, financial reports, and market research firms. Cross-reference findings across multiple credible sources.

For each request, follow this structure:
1. Define research scope and key questions
2. Identify market segments and competitors
3. Gather quantitative data (market size, growth rates)
4. Collect qualitative insights (trends, consumer behavior)
5. Synthesize findings into actionable recommendations

Present findings in executive-ready formats with source citations, highlight key insights, and provide specific recommendations with rationale.

### FINAL INSTRUCTION
Create a system prompt appropriately detailed for the request, using clear language and relevant tool instructions.`,
        placeholder: 'Describe the AI agent you want to create...',
        generationType: 'system-prompt',
      },
    },
    {
      id: 'userPrompt',
      title: 'User Prompt',
      type: 'long-input',
      layout: 'full',
      placeholder: 'Enter context or user message...',
      rows: 3,
    },
    {
      id: 'memories',
      title: 'Memories',
      type: 'short-input',
      layout: 'full',
      placeholder: 'Connect memory block output...',
      mode: 'advanced',
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
      id: 'temperature',
      title: 'Temperature',
      type: 'slider',
      layout: 'half',
      min: 0,
      max: 1,
      defaultValue: 0.5,
      condition: () => ({
        field: 'model',
        value: (() => {
          const allModels = Object.keys(getAllModelProviders())
          return allModels.filter(
            (model) => supportsTemperature(model) && getMaxTemperature(model) === 1
          )
        })(),
      }),
    },
    {
      id: 'temperature',
      title: 'Temperature',
      type: 'slider',
      layout: 'half',
      min: 0,
      max: 2,
      defaultValue: 1,
      condition: () => ({
        field: 'model',
        value: (() => {
          const allModels = Object.keys(getAllModelProviders())
          return allModels.filter(
            (model) => supportsTemperature(model) && getMaxTemperature(model) === 2
          )
        })(),
      }),
    },
    {
      id: 'reasoningEffort',
      title: 'Reasoning Effort',
      type: 'dropdown',
      layout: 'half',
      placeholder: 'Select reasoning effort...',
      options: [
        { label: 'minimal', id: 'minimal' },
        { label: 'low', id: 'low' },
        { label: 'medium', id: 'medium' },
        { label: 'high', id: 'high' },
      ],
      value: () => 'medium',
      condition: {
        field: 'model',
        value: MODELS_WITH_REASONING_EFFORT,
      },
    },
    {
      id: 'verbosity',
      title: 'Verbosity',
      type: 'dropdown',
      layout: 'half',
      placeholder: 'Select verbosity...',
      options: [
        { label: 'low', id: 'low' },
        { label: 'medium', id: 'medium' },
        { label: 'high', id: 'high' },
      ],
      value: () => 'medium',
      condition: {
        field: 'model',
        value: MODELS_WITH_VERBOSITY,
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
      // Hide API key for hosted models and Ollama models
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
      id: 'tools',
      title: 'Tools',
      type: 'tool-input',
      layout: 'full',
      defaultValue: [],
    },
    {
      id: 'responseFormat',
      title: 'Response Format',
      type: 'code',
      layout: 'full',
      placeholder: 'Enter JSON schema...',
      language: 'json',
      wandConfig: {
        enabled: true,
        maintainHistory: true,
        prompt: `You are an expert programmer specializing in creating JSON schemas according to a specific format.
Generate ONLY the JSON schema based on the user's request.
The output MUST be a single, valid JSON object, starting with { and ending with }.
The JSON object MUST have the following top-level properties: 'name' (string), 'description' (string), 'strict' (boolean, usually true), and 'schema' (object).
The 'schema' object must define the structure and MUST contain 'type': 'object', 'properties': {...}, 'additionalProperties': false, and 'required': [...].
Inside 'properties', use standard JSON Schema properties (type, description, enum, items for arrays, etc.).

Current schema: {context}

Do not include any explanations, markdown formatting, or other text outside the JSON object.

Valid Schema Examples:

Example 1:
{
    "name": "reddit_post",
    "description": "Fetches the reddit posts in the given subreddit",
    "strict": true,
    "schema": {
        "type": "object",
        "properties": {
            "title": {
                "type": "string",
                "description": "The title of the post"
            },
            "content": {
                "type": "string",
                "description": "The content of the post"
            }
        },
        "additionalProperties": false,
        "required": [ "title", "content" ]
    }
}

Example 2:
{
    "name": "get_weather",
    "description": "Fetches the current weather for a specific location.",
    "strict": true,
    "schema": {
        "type": "object",
        "properties": {
            "location": {
                "type": "string",
                "description": "The city and state, e.g., San Francisco, CA"
            },
            "unit": {
                "type": "string",
                "description": "Temperature unit",
                "enum": ["celsius", "fahrenheit"]
            }
        },
        "additionalProperties": false,
        "required": ["location", "unit"]
    }
}

Example 3 (Array Input):
{
    "name": "process_items",
    "description": "Processes a list of items with specific IDs.",
    "strict": true,
    "schema": {
        "type": "object",
        "properties": {
            "item_ids": {
                "type": "array",
                "description": "A list of unique item identifiers to process.",
                "items": {
                    "type": "string",
                    "description": "An item ID"
                }
            },
            "processing_mode": {
                "type": "string",
                "description": "The mode for processing",
                "enum": ["fast", "thorough"]
            }
        },
        "additionalProperties": false,
        "required": ["item_ids", "processing_mode"]
    }
}
`,
        placeholder: 'Describe the JSON schema structure you need...',
        generationType: 'json-schema',
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
        const tool = getAllModelProviders()[model]
        if (!tool) {
          throw new Error(`Invalid model selected: ${model}`)
        }
        return tool
      },
      params: (params: Record<string, any>) => {
        // If tools array is provided, handle tool usage control
        if (params.tools && Array.isArray(params.tools)) {
          // Transform tools to include usageControl
          const transformedTools = params.tools
            // Filter out tools set to 'none' - they should never be passed to the provider
            .filter((tool: any) => {
              const usageControl = tool.usageControl || 'auto'
              return usageControl !== 'none'
            })
            .map((tool: any) => {
              const toolConfig = {
                id:
                  tool.type === 'custom-tool'
                    ? tool.schema?.function?.name
                    : tool.operation || getToolIdFromBlock(tool.type),
                name: tool.title,
                description: tool.type === 'custom-tool' ? tool.schema?.function?.description : '',
                params: tool.params || {},
                parameters: tool.type === 'custom-tool' ? tool.schema?.function?.parameters : {},
                usageControl: tool.usageControl || 'auto',
                type: tool.type,
              }
              return toolConfig
            })

          // Log which tools are being passed and which are filtered out
          const filteredOutTools = params.tools
            .filter((tool: any) => (tool.usageControl || 'auto') === 'none')
            .map((tool: any) => tool.title)

          if (filteredOutTools.length > 0) {
            logger.info('Filtered out tools set to none', { tools: filteredOutTools.join(', ') })
          }

          return { ...params, tools: transformedTools }
        }
        return params
      },
    },
  },
  inputs: {
    systemPrompt: { type: 'string', description: 'Initial system instructions' },
    userPrompt: { type: 'string', description: 'User message or context' },
    memories: { type: 'json', description: 'Agent memory data' },
    model: { type: 'string', description: 'AI model to use' },
    apiKey: { type: 'string', description: 'Provider API key' },
    azureEndpoint: { type: 'string', description: 'Azure OpenAI endpoint URL' },
    azureApiVersion: { type: 'string', description: 'Azure API version' },
    responseFormat: {
      type: 'json',
      description: 'JSON response format schema',
      schema: {
        type: 'object',
        properties: {
          name: {
            type: 'string',
            description: 'A name for your schema (optional)',
          },
          schema: {
            type: 'object',
            description: 'The JSON Schema definition',
            properties: {
              type: {
                type: 'string',
                enum: ['object'],
                description: 'Must be "object" for a valid JSON Schema',
              },
              properties: {
                type: 'object',
                description: 'Object containing property definitions',
              },
              required: {
                type: 'array',
                items: { type: 'string' },
                description: 'Array of required property names',
              },
              additionalProperties: {
                type: 'boolean',
                description: 'Whether additional properties are allowed',
              },
            },
            required: ['type', 'properties'],
          },
          strict: {
            type: 'boolean',
            description: 'Whether to enforce strict schema validation',
            default: true,
          },
        },
        required: ['schema'],
      },
    },
    temperature: { type: 'number', description: 'Response randomness level' },
    reasoningEffort: { type: 'string', description: 'Reasoning effort level for GPT-5 models' },
    verbosity: { type: 'string', description: 'Verbosity level for GPT-5 models' },
    tools: { type: 'json', description: 'Available tools configuration' },
  },
  outputs: {
    content: { type: 'string', description: 'Generated response content' },
    model: { type: 'string', description: 'Model used for generation' },
    tokens: { type: 'any', description: 'Token usage statistics' },
    toolCalls: { type: 'any', description: 'Tool calls made' },
  },
}
