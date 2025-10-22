#!/usr/bin/env ts-node
import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'
import { glob } from 'glob'

console.log('Starting documentation generator...')

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
const rootDir = path.resolve(__dirname, '..')

const BLOCKS_PATH = path.join(rootDir, 'apps/sim/blocks/blocks')
const DOCS_OUTPUT_PATH = path.join(rootDir, 'apps/docs/content/docs/en/tools')
const ICONS_PATH = path.join(rootDir, 'apps/sim/components/icons.tsx')

if (!fs.existsSync(DOCS_OUTPUT_PATH)) {
  fs.mkdirSync(DOCS_OUTPUT_PATH, { recursive: true })
}

interface BlockConfig {
  type: string
  name: string
  description: string
  longDescription?: string
  category: string
  bgColor?: string
  outputs?: Record<string, any>
  tools?: {
    access?: string[]
  }
  [key: string]: any
}

function extractIcons(): Record<string, string> {
  try {
    const iconsContent = fs.readFileSync(ICONS_PATH, 'utf-8')
    const icons: Record<string, string> = {}

    const functionDeclarationRegex =
      /export\s+function\s+(\w+Icon)\s*\([^)]*\)\s*{[\s\S]*?return\s*\(\s*<svg[\s\S]*?<\/svg>\s*\)/g
    const arrowFunctionRegex =
      /export\s+const\s+(\w+Icon)\s*=\s*\([^)]*\)\s*=>\s*(\(?\s*<svg[\s\S]*?<\/svg>\s*\)?)/g

    const functionMatches = Array.from(iconsContent.matchAll(functionDeclarationRegex))
    for (const match of functionMatches) {
      const iconName = match[1]
      const svgMatch = match[0].match(/<svg[\s\S]*?<\/svg>/)

      if (iconName && svgMatch) {
        let svgContent = svgMatch[0]
        svgContent = svgContent.replace(/{\.\.\.props}/g, '')
        svgContent = svgContent.replace(/{\.\.\.(props|rest)}/g, '')
        svgContent = svgContent.replace(/width=["'][^"']*["']/g, '')
        svgContent = svgContent.replace(/height=["'][^"']*["']/g, '')
        svgContent = svgContent.replace(/<svg/, '<svg className="block-icon"')
        icons[iconName] = svgContent
      }
    }

    const arrowMatches = Array.from(iconsContent.matchAll(arrowFunctionRegex))
    for (const match of arrowMatches) {
      const iconName = match[1]
      const svgContent = match[2]
      const svgMatch = svgContent.match(/<svg[\s\S]*?<\/svg>/)

      if (iconName && svgMatch) {
        let cleanedSvg = svgMatch[0]
        cleanedSvg = cleanedSvg.replace(/{\.\.\.props}/g, '')
        cleanedSvg = cleanedSvg.replace(/{\.\.\.(props|rest)}/g, '')
        cleanedSvg = cleanedSvg.replace(/width=["'][^"']*["']/g, '')
        cleanedSvg = cleanedSvg.replace(/height=["'][^"']*["']/g, '')
        cleanedSvg = cleanedSvg.replace(/<svg/, '<svg className="block-icon"')
        icons[iconName] = cleanedSvg
      }
    }
    return icons
  } catch (error) {
    console.error('Error extracting icons:', error)
    return {}
  }
}

function extractBlockConfig(fileContent: string): BlockConfig | null {
  try {
    const exportMatch = fileContent.match(/export\s+const\s+(\w+)Block\s*:/)

    if (!exportMatch) {
      console.warn('No block export found in file')
      return null
    }

    const blockName = exportMatch[1]
    const blockType = findBlockType(fileContent, blockName)

    const name = extractStringProperty(fileContent, 'name') || `${blockName} Block`
    const description = extractStringProperty(fileContent, 'description') || ''
    const longDescription = extractStringProperty(fileContent, 'longDescription') || ''
    const category = extractStringProperty(fileContent, 'category') || 'misc'
    const bgColor = extractStringProperty(fileContent, 'bgColor') || '#F5F5F5'
    const iconName = extractIconName(fileContent) || ''

    const outputs = extractOutputs(fileContent)

    const toolsAccess = extractToolsAccess(fileContent)

    return {
      type: blockType || blockName.toLowerCase(),
      name,
      description,
      longDescription,
      category,
      bgColor,
      iconName,
      outputs,
      tools: {
        access: toolsAccess,
      },
    }
  } catch (error) {
    console.error('Error extracting block configuration:', error)
    return null
  }
}

function findBlockType(content: string, blockName: string): string {
  const blockExportRegex = new RegExp(
    `export\\s+const\\s+${blockName}Block\\s*:[^{]*{[\\s\\S]*?type\\s*:\\s*['"]([^'"]+)['"][\\s\\S]*?}`,
    'i'
  )
  const blockExportMatch = content.match(blockExportRegex)
  if (blockExportMatch) return blockExportMatch[1]

  const exportMatch = content.match(new RegExp(`export\\s+const\\s+${blockName}Block\\s*:`))
  if (exportMatch) {
    const afterExport = content.substring(exportMatch.index! + exportMatch[0].length)

    const blockStartMatch = afterExport.match(/{/)
    if (blockStartMatch) {
      const blockStart = blockStartMatch.index!

      let braceCount = 1
      let blockEnd = blockStart + 1

      while (blockEnd < afterExport.length && braceCount > 0) {
        if (afterExport[blockEnd] === '{') braceCount++
        else if (afterExport[blockEnd] === '}') braceCount--
        blockEnd++
      }

      const blockContent = afterExport.substring(blockStart, blockEnd)
      const typeMatch = blockContent.match(/type\s*:\s*['"]([^'"]+)['"]/)
      if (typeMatch) return typeMatch[1]
    }
  }

  return blockName
    .replace(/([A-Z])/g, '_$1')
    .toLowerCase()
    .replace(/^_/, '')
}

function extractStringProperty(content: string, propName: string): string | null {
  const singleQuoteMatch = content.match(new RegExp(`${propName}\\s*:\\s*'(.*?)'`, 'm'))
  if (singleQuoteMatch) return singleQuoteMatch[1]

  const doubleQuoteMatch = content.match(new RegExp(`${propName}\\s*:\\s*"(.*?)"`, 'm'))
  if (doubleQuoteMatch) return doubleQuoteMatch[1]

  const templateMatch = content.match(new RegExp(`${propName}\\s*:\\s*\`([^\`]+)\``, 's'))
  if (templateMatch) {
    let templateContent = templateMatch[1]

    templateContent = templateContent.replace(
      /\$\{[^}]*shouldEnableURLInput[^}]*\?[^:]*:[^}]*\}/g,
      'Upload files directly. '
    )
    templateContent = templateContent.replace(/\$\{[^}]*shouldEnableURLInput[^}]*\}/g, 'false')

    templateContent = templateContent.replace(/\$\{[^}]+\}/g, '')

    templateContent = templateContent.replace(/\s+/g, ' ').trim()

    return templateContent
  }

  return null
}

function extractIconName(content: string): string | null {
  const iconMatch = content.match(/icon\s*:\s*(\w+Icon)/)
  return iconMatch ? iconMatch[1] : null
}

function extractOutputs(content: string): Record<string, any> {
  const outputsStart = content.search(/outputs\s*:\s*{/)
  if (outputsStart === -1) return {}

  const openBracePos = content.indexOf('{', outputsStart)
  if (openBracePos === -1) return {}

  let braceCount = 1
  let pos = openBracePos + 1

  while (pos < content.length && braceCount > 0) {
    if (content[pos] === '{') {
      braceCount++
    } else if (content[pos] === '}') {
      braceCount--
    }
    pos++
  }

  if (braceCount === 0) {
    const outputsContent = content.substring(openBracePos + 1, pos - 1).trim()
    const outputs: Record<string, any> = {}

    const fieldRegex = /(\w+)\s*:\s*{/g
    let match
    const fieldPositions: Array<{ name: string; start: number }> = []

    while ((match = fieldRegex.exec(outputsContent)) !== null) {
      fieldPositions.push({
        name: match[1],
        start: match.index + match[0].length - 1,
      })
    }

    fieldPositions.forEach((field) => {
      const startPos = field.start
      let braceCount = 1
      let endPos = startPos + 1

      while (endPos < outputsContent.length && braceCount > 0) {
        if (outputsContent[endPos] === '{') {
          braceCount++
        } else if (outputsContent[endPos] === '}') {
          braceCount--
        }
        endPos++
      }

      if (braceCount === 0) {
        const fieldContent = outputsContent.substring(startPos + 1, endPos - 1).trim()

        const typeMatch = fieldContent.match(/type\s*:\s*['"](.*?)['"]/)
        const descriptionMatch = fieldContent.match(/description\s*:\s*['"](.*?)['"]/)

        if (typeMatch) {
          outputs[field.name] = {
            type: typeMatch[1],
            description: descriptionMatch
              ? descriptionMatch[1]
              : `${field.name} output from the block`,
          }
        }
      }
    })

    if (Object.keys(outputs).length > 0) {
      return outputs
    }

    const flatFieldMatches = outputsContent.match(/(\w+)\s*:\s*['"](.*?)['"]/g)

    if (flatFieldMatches && flatFieldMatches.length > 0) {
      flatFieldMatches.forEach((fieldMatch) => {
        const fieldParts = fieldMatch.match(/(\w+)\s*:\s*['"](.*?)['"]/)
        if (fieldParts) {
          const fieldName = fieldParts[1]
          const fieldType = fieldParts[2]

          outputs[fieldName] = {
            type: fieldType,
            description: `${fieldName} output from the block`,
          }
        }
      })

      if (Object.keys(outputs).length > 0) {
        return outputs
      }
    }
  }

  return {}
}

function extractToolsAccess(content: string): string[] {
  const accessMatch = content.match(/access\s*:\s*\[\s*([^\]]+)\s*\]/)
  if (!accessMatch) return []

  const accessContent = accessMatch[1]
  const tools: string[] = []

  const toolMatches = accessContent.match(/['"]([^'"]+)['"]/g)
  if (toolMatches) {
    toolMatches.forEach((toolText) => {
      const match = toolText.match(/['"]([^'"]+)['"]/)
      if (match) {
        tools.push(match[1])
      }
    })
  }

  return tools
}

function extractToolInfo(
  toolName: string,
  fileContent: string
): {
  description: string
  params: Array<{ name: string; type: string; required: boolean; description: string }>
  outputs: Record<string, any>
} | null {
  try {
    const toolConfigRegex =
      /params\s*:\s*{([\s\S]*?)},?\s*(?:outputs|oauth|request|directExecution|postProcess|transformResponse)/
    const toolConfigMatch = fileContent.match(toolConfigRegex)

    const descriptionRegex = /description\s*:\s*['"](.*?)['"].*/
    const descriptionMatch = fileContent.match(descriptionRegex)
    const description = descriptionMatch ? descriptionMatch[1] : 'No description available'

    const params: Array<{ name: string; type: string; required: boolean; description: string }> = []

    if (toolConfigMatch) {
      const paramsContent = toolConfigMatch[1]

      const paramBlocksRegex = /(\w+)\s*:\s*{/g
      let paramMatch
      const paramPositions: Array<{ name: string; start: number; content: string }> = []

      while ((paramMatch = paramBlocksRegex.exec(paramsContent)) !== null) {
        const paramName = paramMatch[1]
        const startPos = paramMatch.index + paramMatch[0].length - 1

        let braceCount = 1
        let endPos = startPos + 1

        while (endPos < paramsContent.length && braceCount > 0) {
          if (paramsContent[endPos] === '{') {
            braceCount++
          } else if (paramsContent[endPos] === '}') {
            braceCount--
          }
          endPos++
        }

        if (braceCount === 0) {
          const paramBlock = paramsContent.substring(startPos + 1, endPos - 1).trim()
          paramPositions.push({ name: paramName, start: startPos, content: paramBlock })
        }
      }

      for (const param of paramPositions) {
        const paramName = param.name
        const paramBlock = param.content

        if (paramName === 'accessToken' || paramName === 'params' || paramName === 'tools') {
          continue
        }

        const typeMatch = paramBlock.match(/type\s*:\s*['"]([^'"]+)['"]/)
        const requiredMatch = paramBlock.match(/required\s*:\s*(true|false)/)

        let descriptionMatch = paramBlock.match(/description\s*:\s*'(.*?)'(?=\s*[,}])/s)
        if (!descriptionMatch) {
          descriptionMatch = paramBlock.match(/description\s*:\s*"(.*?)"(?=\s*[,}])/s)
        }
        if (!descriptionMatch) {
          descriptionMatch = paramBlock.match(/description\s*:\s*`([^`]+)`/s)
        }
        if (!descriptionMatch) {
          descriptionMatch = paramBlock.match(
            /description\s*:\s*['"]([^'"]*(?:\n[^'"]*)*?)['"](?=\s*[,}])/s
          )
        }

        params.push({
          name: paramName,
          type: typeMatch ? typeMatch[1] : 'string',
          required: requiredMatch ? requiredMatch[1] === 'true' : false,
          description: descriptionMatch ? descriptionMatch[1] : 'No description',
        })
      }
    }

    let outputs: Record<string, any> = {}
    const outputsFieldRegex =
      /outputs\s*:\s*{([\s\S]*?)}\s*,?\s*(?:oauth|params|request|directExecution|postProcess|transformResponse|$|\})/
    const outputsFieldMatch = fileContent.match(outputsFieldRegex)

    if (outputsFieldMatch) {
      const outputsContent = outputsFieldMatch[1]
      outputs = parseToolOutputsField(outputsContent)
      console.log(`Found tool outputs field for ${toolName}:`, Object.keys(outputs))
    }

    return {
      description,
      params,
      outputs,
    }
  } catch (error) {
    console.error(`Error extracting info for tool ${toolName}:`, error)
    return null
  }
}

function formatOutputStructure(outputs: Record<string, any>, indentLevel = 0): string {
  let result = ''

  for (const [key, output] of Object.entries(outputs)) {
    let type = 'unknown'
    let description = `${key} output from the tool`

    if (typeof output === 'object' && output !== null) {
      if (output.type) {
        type = output.type
      }

      if (output.description) {
        description = output.description
      }
    }

    const escapedDescription = description
      .replace(/\|/g, '\\|')
      .replace(/\{/g, '\\{')
      .replace(/\}/g, '\\}')
      .replace(/\(/g, '\\(')
      .replace(/\)/g, '\\)')
      .replace(/\[/g, '\\[')
      .replace(/\]/g, '\\]')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')

    let prefix = ''
    if (indentLevel === 1) {
      prefix = '↳ '
    } else if (indentLevel >= 2) {
      prefix = '  ↳ '
    }

    if (typeof output === 'object' && output !== null && output.type === 'array') {
      result += `| ${prefix}\`${key}\` | ${type} | ${escapedDescription} |\n`

      if (output.items?.properties) {
        const arrayItemsResult = formatOutputStructure(output.items.properties, indentLevel + 2)
        result += arrayItemsResult
      }
    } else if (
      typeof output === 'object' &&
      output !== null &&
      output.properties &&
      (output.type === 'object' || output.type === 'json')
    ) {
      result += `| ${prefix}\`${key}\` | ${type} | ${escapedDescription} |\n`

      const nestedResult = formatOutputStructure(output.properties, indentLevel + 1)
      result += nestedResult
    } else {
      result += `| ${prefix}\`${key}\` | ${type} | ${escapedDescription} |\n`
    }
  }

  return result
}

function parseToolOutputsField(outputsContent: string): Record<string, any> {
  const outputs: Record<string, any> = {}

  const braces: Array<{ type: 'open' | 'close'; pos: number; level: number }> = []
  for (let i = 0; i < outputsContent.length; i++) {
    if (outputsContent[i] === '{') {
      braces.push({ type: 'open', pos: i, level: 0 })
    } else if (outputsContent[i] === '}') {
      braces.push({ type: 'close', pos: i, level: 0 })
    }
  }

  let currentLevel = 0
  for (const brace of braces) {
    if (brace.type === 'open') {
      brace.level = currentLevel
      currentLevel++
    } else {
      currentLevel--
      brace.level = currentLevel
    }
  }

  const fieldStartRegex = /(\w+)\s*:\s*{/g
  let match
  const fieldPositions: Array<{ name: string; start: number; end: number; level: number }> = []

  while ((match = fieldStartRegex.exec(outputsContent)) !== null) {
    const fieldName = match[1]
    const bracePos = match.index + match[0].length - 1

    const openBrace = braces.find((b) => b.type === 'open' && b.pos === bracePos)
    if (openBrace) {
      let braceCount = 1
      let endPos = bracePos + 1

      while (endPos < outputsContent.length && braceCount > 0) {
        if (outputsContent[endPos] === '{') {
          braceCount++
        } else if (outputsContent[endPos] === '}') {
          braceCount--
        }
        endPos++
      }

      fieldPositions.push({
        name: fieldName,
        start: bracePos,
        end: endPos,
        level: openBrace.level,
      })
    }
  }

  const topLevelFields = fieldPositions.filter((f) => f.level === 0)

  topLevelFields.forEach((field) => {
    const fieldContent = outputsContent.substring(field.start + 1, field.end - 1).trim()

    const parsedField = parseFieldContent(fieldContent)
    if (parsedField) {
      outputs[field.name] = parsedField
    }
  })

  return outputs
}

function parseFieldContent(fieldContent: string): any {
  const typeMatch = fieldContent.match(/type\s*:\s*['"]([^'"]+)['"]/)
  const descMatch = fieldContent.match(/description\s*:\s*['"`]([^'"`\n]+)['"`]/)

  if (!typeMatch) return null

  const fieldType = typeMatch[1]
  const description = descMatch ? descMatch[1] : ''

  const result: any = {
    type: fieldType,
    description: description,
  }

  if (fieldType === 'object' || fieldType === 'json') {
    const propertiesRegex = /properties\s*:\s*{/
    const propertiesStart = fieldContent.search(propertiesRegex)

    if (propertiesStart !== -1) {
      const braceStart = fieldContent.indexOf('{', propertiesStart)
      let braceCount = 1
      let braceEnd = braceStart + 1

      while (braceEnd < fieldContent.length && braceCount > 0) {
        if (fieldContent[braceEnd] === '{') braceCount++
        else if (fieldContent[braceEnd] === '}') braceCount--
        braceEnd++
      }

      if (braceCount === 0) {
        const propertiesContent = fieldContent.substring(braceStart + 1, braceEnd - 1).trim()
        result.properties = parsePropertiesContent(propertiesContent)
      }
    }
  }

  const itemsRegex = /items\s*:\s*{/
  const itemsStart = fieldContent.search(itemsRegex)

  if (itemsStart !== -1) {
    const braceStart = fieldContent.indexOf('{', itemsStart)
    let braceCount = 1
    let braceEnd = braceStart + 1

    while (braceEnd < fieldContent.length && braceCount > 0) {
      if (fieldContent[braceEnd] === '{') braceCount++
      else if (fieldContent[braceEnd] === '}') braceCount--
      braceEnd++
    }

    if (braceCount === 0) {
      const itemsContent = fieldContent.substring(braceStart + 1, braceEnd - 1).trim()
      const itemsType = itemsContent.match(/type\s*:\s*['"]([^'"]+)['"]/)

      const propertiesStart = itemsContent.search(/properties\s*:\s*{/)
      const searchContent =
        propertiesStart >= 0 ? itemsContent.substring(0, propertiesStart) : itemsContent
      const itemsDesc = searchContent.match(/description\s*:\s*['"`]([^'"`\n]+)['"`]/)

      result.items = {
        type: itemsType ? itemsType[1] : 'object',
        description: itemsDesc ? itemsDesc[1] : '',
      }

      const itemsPropertiesRegex = /properties\s*:\s*{/
      const itemsPropsStart = itemsContent.search(itemsPropertiesRegex)

      if (itemsPropsStart !== -1) {
        const propsBraceStart = itemsContent.indexOf('{', itemsPropsStart)
        let propsBraceCount = 1
        let propsBraceEnd = propsBraceStart + 1

        while (propsBraceEnd < itemsContent.length && propsBraceCount > 0) {
          if (itemsContent[propsBraceEnd] === '{') propsBraceCount++
          else if (itemsContent[propsBraceEnd] === '}') propsBraceCount--
          propsBraceEnd++
        }

        if (propsBraceCount === 0) {
          const itemsPropsContent = itemsContent
            .substring(propsBraceStart + 1, propsBraceEnd - 1)
            .trim()
          result.items.properties = parsePropertiesContent(itemsPropsContent)
        }
      }
    }
  }

  return result
}

function parsePropertiesContent(propertiesContent: string): Record<string, any> {
  const properties: Record<string, any> = {}

  const propStartRegex = /(\w+)\s*:\s*{/g
  let match
  const propPositions: Array<{ name: string; start: number; content: string }> = []

  while ((match = propStartRegex.exec(propertiesContent)) !== null) {
    const propName = match[1]

    if (propName === 'items' || propName === 'properties') {
      continue
    }

    const startPos = match.index + match[0].length - 1

    let braceCount = 1
    let endPos = startPos + 1

    while (endPos < propertiesContent.length && braceCount > 0) {
      if (propertiesContent[endPos] === '{') {
        braceCount++
      } else if (propertiesContent[endPos] === '}') {
        braceCount--
      }
      endPos++
    }

    if (braceCount === 0) {
      const propContent = propertiesContent.substring(startPos + 1, endPos - 1).trim()

      const hasDescription = /description\s*:\s*/.test(propContent)
      const hasProperties = /properties\s*:\s*{/.test(propContent)
      const hasItems = /items\s*:\s*{/.test(propContent)
      const isTypeOnly =
        !hasDescription &&
        !hasProperties &&
        !hasItems &&
        /^type\s*:\s*['"].*?['"]\s*,?\s*$/.test(propContent)

      if (!isTypeOnly) {
        propPositions.push({
          name: propName,
          start: startPos,
          content: propContent,
        })
      }
    }
  }

  propPositions.forEach((prop) => {
    const parsedProp = parseFieldContent(prop.content)
    if (parsedProp) {
      properties[prop.name] = parsedProp
    }
  })

  return properties
}

async function getToolInfo(toolName: string): Promise<{
  description: string
  params: Array<{ name: string; type: string; required: boolean; description: string }>
  outputs: Record<string, any>
} | null> {
  try {
    const parts = toolName.split('_')

    let toolPrefix = ''
    let toolSuffix = ''

    for (let i = parts.length - 1; i >= 1; i--) {
      const possiblePrefix = parts.slice(0, i).join('_')
      const possibleSuffix = parts.slice(i).join('_')

      const toolDirPath = path.join(rootDir, `apps/sim/tools/${possiblePrefix}`)

      if (fs.existsSync(toolDirPath) && fs.statSync(toolDirPath).isDirectory()) {
        toolPrefix = possiblePrefix
        toolSuffix = possibleSuffix
        break
      }
    }

    if (!toolPrefix) {
      toolPrefix = parts[0]
      toolSuffix = parts.slice(1).join('_')
    }

    const possibleLocations = []

    possibleLocations.push(path.join(rootDir, `apps/sim/tools/${toolPrefix}/${toolSuffix}.ts`))

    const camelCaseSuffix = toolSuffix
      .split('_')
      .map((part, i) => (i === 0 ? part : part.charAt(0).toUpperCase() + part.slice(1)))
      .join('')
    possibleLocations.push(path.join(rootDir, `apps/sim/tools/${toolPrefix}/${camelCaseSuffix}.ts`))

    possibleLocations.push(path.join(rootDir, `apps/sim/tools/${toolPrefix}/index.ts`))

    let toolFileContent = ''

    for (const location of possibleLocations) {
      if (fs.existsSync(location)) {
        toolFileContent = fs.readFileSync(location, 'utf-8')
        break
      }
    }

    if (!toolFileContent) {
      console.warn(`Could not find definition for tool: ${toolName}`)
      return null
    }

    return extractToolInfo(toolName, toolFileContent)
  } catch (error) {
    console.error(`Error getting info for tool ${toolName}:`, error)
    return null
  }
}

function extractManualContent(existingContent: string): Record<string, string> {
  const manualSections: Record<string, string> = {}
  const manualContentRegex =
    /\{\/\*\s*MANUAL-CONTENT-START:(\w+)\s*\*\/\}([\s\S]*?)\{\/\*\s*MANUAL-CONTENT-END\s*\*\/\}/g

  let match
  while ((match = manualContentRegex.exec(existingContent)) !== null) {
    const sectionName = match[1]
    const content = match[2].trim()
    manualSections[sectionName] = content
    console.log(`Found manual content for section: ${sectionName}`)
  }

  return manualSections
}

function mergeWithManualContent(
  generatedMarkdown: string,
  existingContent: string | null,
  manualSections: Record<string, string>
): string {
  if (!existingContent || Object.keys(manualSections).length === 0) {
    return generatedMarkdown
  }

  console.log('Merging manual content with generated markdown')

  console.log(`Found ${Object.keys(manualSections).length} manual sections`)
  Object.keys(manualSections).forEach((section) => {
    console.log(`  - ${section}: ${manualSections[section].substring(0, 20)}...`)
  })

  let mergedContent = generatedMarkdown

  Object.entries(manualSections).forEach(([sectionName, content]) => {
    const insertionPoints: Record<string, { regex: RegExp }> = {
      intro: {
        regex: /<BlockInfoCard[\s\S]*?<\/svg>`}\s*\/>/,
      },
      usage: {
        regex: /## Usage Instructions/,
      },
      outputs: {
        regex: /## Outputs/,
      },
      notes: {
        regex: /## Notes/,
      },
    }

    const insertionPoint = insertionPoints[sectionName]

    if (insertionPoint) {
      const match = mergedContent.match(insertionPoint.regex)

      if (match && match.index !== undefined) {
        const insertPosition = match.index + match[0].length
        console.log(`Inserting ${sectionName} content after position ${insertPosition}`)
        mergedContent = `${mergedContent.slice(0, insertPosition)}\n\n{/* MANUAL-CONTENT-START:${sectionName} */}\n${content}\n{/* MANUAL-CONTENT-END */}\n${mergedContent.slice(insertPosition)}`
      } else {
        console.log(
          `Could not find insertion point for ${sectionName}, regex pattern: ${insertionPoint.regex}`
        )
      }
    } else {
      console.log(`No insertion point defined for section ${sectionName}`)
    }
  })

  return mergedContent
}

async function generateBlockDoc(blockPath: string, icons: Record<string, string>) {
  try {
    const blockFileName = path.basename(blockPath, '.ts')
    if (blockFileName.endsWith('.test')) {
      return
    }

    const fileContent = fs.readFileSync(blockPath, 'utf-8')

    const blockConfig = extractBlockConfig(fileContent)

    if (!blockConfig || !blockConfig.type) {
      console.warn(`Skipping ${blockFileName} - not a valid block config`)
      return
    }

    if (blockConfig.type.includes('_trigger') || blockConfig.type.includes('_webhook')) {
      console.log(`Skipping ${blockConfig.type} - contains '_trigger'`)
      return
    }

    if (
      (blockConfig.category === 'blocks' &&
        blockConfig.type !== 'memory' &&
        blockConfig.type !== 'knowledge') ||
      blockConfig.type === 'evaluator' ||
      blockConfig.type === 'number'
    ) {
      return
    }

    const outputFilePath = path.join(DOCS_OUTPUT_PATH, `${blockConfig.type}.mdx`)

    let existingContent: string | null = null
    if (fs.existsSync(outputFilePath)) {
      existingContent = fs.readFileSync(outputFilePath, 'utf-8')
      console.log(`Existing file found for ${blockConfig.type}.mdx, checking for manual content...`)
    }

    const manualSections = existingContent ? extractManualContent(existingContent) : {}

    const markdown = await generateMarkdownForBlock(blockConfig, icons)

    let finalContent = markdown
    if (Object.keys(manualSections).length > 0) {
      console.log(`Found manual content in ${blockConfig.type}.mdx, merging...`)
      finalContent = mergeWithManualContent(markdown, existingContent, manualSections)
    } else {
      console.log(`No manual content found in ${blockConfig.type}.mdx`)
    }

    fs.writeFileSync(outputFilePath, finalContent)
    console.log(`Generated documentation for ${blockConfig.type}`)
  } catch (error) {
    console.error(`Error processing ${blockPath}:`, error)
  }
}

async function generateMarkdownForBlock(
  blockConfig: BlockConfig,
  icons: Record<string, string>
): Promise<string> {
  const {
    type,
    name,
    description,
    longDescription,
    category,
    bgColor,
    iconName,
    outputs = {},
    tools = { access: [] },
  } = blockConfig

  const iconSvg = iconName && icons[iconName] ? icons[iconName] : null

  let outputsSection = ''

  if (outputs && Object.keys(outputs).length > 0) {
    outputsSection = '## Outputs\n\n'

    outputsSection += '| Output | Type | Description |\n'
    outputsSection += '| ------ | ---- | ----------- |\n'

    for (const outputKey in outputs) {
      const output = outputs[outputKey]

      const escapedDescription = output.description
        ? output.description
            .replace(/\|/g, '\\|')
            .replace(/\{/g, '\\{')
            .replace(/\}/g, '\\}')
            .replace(/\(/g, '\\(')
            .replace(/\)/g, '\\)')
            .replace(/\[/g, '\\[')
            .replace(/\]/g, '\\]')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
        : `Output from ${outputKey}`

      if (typeof output.type === 'string') {
        outputsSection += `| \`${outputKey}\` | ${output.type} | ${escapedDescription} |\n`
      } else if (output.type && typeof output.type === 'object') {
        outputsSection += `| \`${outputKey}\` | object | ${escapedDescription} |\n`

        for (const propName in output.type) {
          const propType = output.type[propName]
          const commentMatch =
            propName && output.type[propName]._comment
              ? output.type[propName]._comment
              : `${propName} of the ${outputKey}`

          outputsSection += `| ↳ \`${propName}\` | ${propType} | ${commentMatch} |\n`
        }
      } else if (output.properties) {
        outputsSection += `| \`${outputKey}\` | object | ${escapedDescription} |\n`

        for (const propName in output.properties) {
          const prop = output.properties[propName]
          const escapedPropertyDescription = prop.description
            ? prop.description
                .replace(/\|/g, '\\|')
                .replace(/\{/g, '\\{')
                .replace(/\}/g, '\\}')
                .replace(/\(/g, '\\(')
                .replace(/\)/g, '\\)')
                .replace(/\[/g, '\\[')
                .replace(/\]/g, '\\]')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
            : `The ${propName} of the ${outputKey}`

          outputsSection += `| ↳ \`${propName}\` | ${prop.type} | ${escapedPropertyDescription} |\n`
        }
      }
    }
  } else {
    outputsSection = 'This block does not produce any outputs.'
  }

  let toolsSection = ''
  if (tools.access?.length) {
    toolsSection = '## Tools\n\n'

    for (const tool of tools.access) {
      toolsSection += `### \`${tool}\`\n\n`

      console.log(`Getting info for tool: ${tool}`)
      const toolInfo = await getToolInfo(tool)

      if (toolInfo) {
        if (toolInfo.description && toolInfo.description !== 'No description available') {
          toolsSection += `${toolInfo.description}\n\n`
        }

        toolsSection += '#### Input\n\n'
        toolsSection += '| Parameter | Type | Required | Description |\n'
        toolsSection += '| --------- | ---- | -------- | ----------- |\n'

        if (toolInfo.params.length > 0) {
          for (const param of toolInfo.params) {
            const escapedDescription = param.description
              ? param.description
                  .replace(/\|/g, '\\|')
                  .replace(/\{/g, '\\{')
                  .replace(/\}/g, '\\}')
                  .replace(/\(/g, '\\(')
                  .replace(/\)/g, '\\)')
                  .replace(/\[/g, '\\[')
                  .replace(/\]/g, '\\]')
                  .replace(/</g, '&lt;')
                  .replace(/>/g, '&gt;')
              : 'No description'

            toolsSection += `| \`${param.name}\` | ${param.type} | ${param.required ? 'Yes' : 'No'} | ${escapedDescription} |\n`
          }
        }

        toolsSection += '\n#### Output\n\n'

        if (Object.keys(toolInfo.outputs).length > 0) {
          toolsSection += '| Parameter | Type | Description |\n'
          toolsSection += '| --------- | ---- | ----------- |\n'

          toolsSection += formatOutputStructure(toolInfo.outputs)
        } else if (Object.keys(outputs).length > 0) {
          toolsSection += '| Parameter | Type | Description |\n'
          toolsSection += '| --------- | ---- | ----------- |\n'

          for (const [key, output] of Object.entries(outputs)) {
            let type = 'string'
            let description = `${key} output from the tool`

            if (typeof output === 'string') {
              type = output
            } else if (typeof output === 'object' && output !== null) {
              if ('type' in output && typeof output.type === 'string') {
                type = output.type
              }
              if ('description' in output && typeof output.description === 'string') {
                description = output.description
              }
            }

            const escapedDescription = description
              .replace(/\|/g, '\\|')
              .replace(/\{/g, '\\{')
              .replace(/\}/g, '\\}')
              .replace(/\(/g, '\\(')
              .replace(/\)/g, '\\)')
              .replace(/\[/g, '\\[')
              .replace(/\]/g, '\\]')
              .replace(/</g, '&lt;')
              .replace(/>/g, '&gt;')

            toolsSection += `| \`${key}\` | ${type} | ${escapedDescription} |\n`
          }
        } else {
          toolsSection += 'This tool does not produce any outputs.\n'
        }
      }

      toolsSection += '\n'
    }
  }

  let usageInstructions = ''
  if (longDescription) {
    usageInstructions = `## Usage Instructions\n\n${longDescription}\n\n`
  }

  return `---
title: ${name}
description: ${description}
---

import { BlockInfoCard } from "@/components/ui/block-info-card"

<BlockInfoCard 
  type="${type}"
  color="${bgColor || '#F5F5F5'}"
  icon={${iconSvg ? 'true' : 'false'}}
  iconSvg={\`${iconSvg || ''}\`}
/>

${usageInstructions}

${toolsSection}

## Notes

- Category: \`${category}\`
- Type: \`${type}\`
`
}

async function generateAllBlockDocs() {
  try {
    const icons = extractIcons()

    const blockFiles = await glob(`${BLOCKS_PATH}/*.ts`)

    for (const blockFile of blockFiles) {
      await generateBlockDoc(blockFile, icons)
    }

    updateMetaJson()

    return true
  } catch (error) {
    console.error('Error generating documentation:', error)
    return false
  }
}

function updateMetaJson() {
  const metaJsonPath = path.join(DOCS_OUTPUT_PATH, 'meta.json')

  const blockFiles = fs
    .readdirSync(DOCS_OUTPUT_PATH)
    .filter((file: string) => file.endsWith('.mdx'))
    .map((file: string) => path.basename(file, '.mdx'))

  const items = [
    ...(blockFiles.includes('index') ? ['index'] : []),
    ...blockFiles.filter((file: string) => file !== 'index').sort(),
  ]

  const metaJson = {
    pages: items,
  }

  fs.writeFileSync(metaJsonPath, JSON.stringify(metaJson, null, 2))
}

generateAllBlockDocs()
  .then((success) => {
    if (success) {
      console.log('Documentation generation completed successfully')
      process.exit(0)
    } else {
      console.error('Documentation generation failed')
      process.exit(1)
    }
  })
  .catch((error) => {
    console.error('Fatal error:', error)
    process.exit(1)
  })
