'use client'

import { useEffect, useRef, useState } from 'react'
import { Brain } from 'lucide-react'
import { cn } from '@/lib/utils'

interface ThinkingBlockProps {
  content: string
  isStreaming?: boolean
  duration?: number // Persisted duration from content block
  startTime?: number // Persisted start time from content block
}

export function ThinkingBlock({
  content,
  isStreaming = false,
  duration: persistedDuration,
  startTime: persistedStartTime,
}: ThinkingBlockProps) {
  const [isExpanded, setIsExpanded] = useState(false)
  const [duration, setDuration] = useState(persistedDuration ?? 0)
  // Track if the user explicitly collapsed while streaming; sticky per block instance
  const userCollapsedRef = useRef<boolean>(false)
  // Keep a stable reference to start time that updates when prop changes
  const startTimeRef = useRef<number>(persistedStartTime ?? Date.now())
  useEffect(() => {
    if (typeof persistedStartTime === 'number') {
      startTimeRef.current = persistedStartTime
    }
  }, [persistedStartTime])

  useEffect(() => {
    // Auto-collapse when streaming ends and reset userCollapsed flag
    if (!isStreaming) {
      setIsExpanded(false)
      userCollapsedRef.current = false
      return
    }
    // Expand once there is visible content while streaming, unless user collapsed
    if (!userCollapsedRef.current && content && content.trim().length > 0) {
      setIsExpanded(true)
    }
  }, [isStreaming, content])

  useEffect(() => {
    // If we already have a persisted duration, just use it
    if (typeof persistedDuration === 'number') {
      setDuration(persistedDuration)
      return
    }

    if (isStreaming) {
      const interval = setInterval(() => {
        setDuration(Date.now() - startTimeRef.current)
      }, 100)
      return () => clearInterval(interval)
    }

    // Not streaming and no persisted duration: compute final duration once
    setDuration(Date.now() - startTimeRef.current)
  }, [isStreaming, persistedDuration])

  // Format duration
  const formatDuration = (ms: number) => {
    if (ms < 1000) return `${ms}ms`
    const seconds = (ms / 1000).toFixed(1)
    return `${seconds}s`
  }

  return (
    <div className='mt-1 mb-0'>
      <button
        onClick={() => {
          setIsExpanded((v) => {
            const next = !v
            // If user collapses during streaming, remember to not auto-expand again
            if (!next && isStreaming) userCollapsedRef.current = true
            return next
          })
        }}
        className={cn(
          'mb-1 inline-flex items-center gap-1 text-[11px] text-gray-400 transition-colors hover:text-gray-500',
          'font-normal italic'
        )}
        type='button'
      >
        <Brain className='h-3 w-3' />
        <span>
          Thought for {formatDuration(duration)}
          {isExpanded ? ' (click to collapse)' : ''}
        </span>
        {isStreaming && (
          <span className='inline-flex h-1 w-1 animate-pulse rounded-full bg-gray-400' />
        )}
      </button>

      {isExpanded && (
        <div className='ml-1 border-gray-200 border-l-2 pl-2 dark:border-gray-700'>
          <pre className='whitespace-pre-wrap font-mono text-[11px] text-gray-400 dark:text-gray-500'>
            {content}
            {isStreaming && (
              <span className='ml-1 inline-block h-2 w-1 animate-pulse bg-gray-400' />
            )}
          </pre>
        </div>
      )}
    </div>
  )
}
