package server

import (
	"strings"

	"kiro2api/config"
	"kiro2api/logger"
)

// ThinkingParseState thinking 标签解析状态
type ThinkingParseState int

const (
	// StateNormal 正常状态，未检测到 thinking 标签
	StateNormal ThinkingParseState = iota
	// StateInThinking 在 thinking 块内
	StateInThinking
	// StateAfterThinking thinking 块已结束
	StateAfterThinking
)

// ThinkingParser thinking 标签解析器
// 用于从流式文本中提取 <thinking>...</thinking> 内容
type ThinkingParser struct {
	state           ThinkingParseState
	thinkingBuffer  strings.Builder // thinking 内容缓冲
	pendingBuffer   strings.Builder // 待处理的部分标签缓冲
	thinkingStarted bool            // thinking 块是否已开始发送
	thinkingStopped bool            // thinking 块是否已结束发送
	textStarted     bool            // text 块是否已开始发送
}

// NewThinkingParser 创建 thinking 解析器
func NewThinkingParser() *ThinkingParser {
	return &ThinkingParser{
		state: StateNormal,
	}
}

// ThinkingParseResult 解析结果
type ThinkingParseResult struct {
	ThinkingContent string // thinking 内容（如果有）
	TextContent     string // 正文内容（如果有）
	ThinkingStart   bool   // 是否检测到 thinking 开始
	ThinkingEnd     bool   // 是否检测到 thinking 结束
}

// Parse 解析文本内容，分离 thinking 和正文
func (tp *ThinkingParser) Parse(text string) ThinkingParseResult {
	result := ThinkingParseResult{}

	// 如果有待处理的缓冲，先合并
	if tp.pendingBuffer.Len() > 0 {
		text = tp.pendingBuffer.String() + text
		tp.pendingBuffer.Reset()
	}

	for len(text) > 0 {
		switch tp.state {
		case StateNormal:
			// 查找 <thinking> 开始标签
			idx := strings.Index(text, config.ThinkingTagOpen)
			if idx == -1 {
				// 检查是否有部分标签（可能跨分片）
				partialIdx := tp.findPartialTag(text, config.ThinkingTagOpen)
				if partialIdx >= 0 {
					// 输出部分标签之前的内容
					result.TextContent += text[:partialIdx]
					// 缓存可能的部分标签
					tp.pendingBuffer.WriteString(text[partialIdx:])
					text = ""
				} else {
					// 没有标签，全部作为正文
					result.TextContent += text
					text = ""
				}
			} else {
				// 找到开始标签
				if idx > 0 {
					result.TextContent += text[:idx]
				}
				tp.state = StateInThinking
				result.ThinkingStart = true
				text = text[idx+len(config.ThinkingTagOpen):]
				logger.Debug("检测到 thinking 开始标签")
			}

		case StateInThinking:
			// 查找 </thinking> 结束标签
			idx := strings.Index(text, config.ThinkingTagClose)
			if idx == -1 {
				// 检查是否有部分标签
				partialIdx := tp.findPartialTag(text, config.ThinkingTagClose)
				if partialIdx >= 0 {
					// 输出部分标签之前的内容
					result.ThinkingContent += text[:partialIdx]
					tp.thinkingBuffer.WriteString(text[:partialIdx])
					// 缓存可能的部分标签
					tp.pendingBuffer.WriteString(text[partialIdx:])
					text = ""
				} else {
					// 没有结束标签，全部作为 thinking 内容
					result.ThinkingContent += text
					tp.thinkingBuffer.WriteString(text)
					text = ""
				}
			} else {
				// 找到结束标签
				if idx > 0 {
					result.ThinkingContent += text[:idx]
					tp.thinkingBuffer.WriteString(text[:idx])
				}
				tp.state = StateAfterThinking
				result.ThinkingEnd = true
				text = text[idx+len(config.ThinkingTagClose):]
				logger.Debug("检测到 thinking 结束标签",
					logger.Int("thinking_length", tp.thinkingBuffer.Len()))
			}

		case StateAfterThinking:
			// thinking 已结束，剩余内容都是正文
			result.TextContent += text
			text = ""
		}
	}

	return result
}

// findPartialTag 查找可能的部分标签
// 返回部分标签开始的位置，如果没有返回 -1
func (tp *ThinkingParser) findPartialTag(text string, tag string) int {
	// 检查文本末尾是否可能是标签的开始部分
	for i := 1; i < len(tag) && i <= len(text); i++ {
		suffix := text[len(text)-i:]
		prefix := tag[:i]
		if suffix == prefix {
			return len(text) - i
		}
	}
	return -1
}

// GetState 获取当前解析状态
func (tp *ThinkingParser) GetState() ThinkingParseState {
	return tp.state
}

// IsInThinking 是否在 thinking 块内
func (tp *ThinkingParser) IsInThinking() bool {
	return tp.state == StateInThinking
}

// IsAfterThinking thinking 块是否已结束
func (tp *ThinkingParser) IsAfterThinking() bool {
	return tp.state == StateAfterThinking
}

// GetThinkingContent 获取完整的 thinking 内容
func (tp *ThinkingParser) GetThinkingContent() string {
	return tp.thinkingBuffer.String()
}

// Reset 重置解析器状态
func (tp *ThinkingParser) Reset() {
	tp.state = StateNormal
	tp.thinkingBuffer.Reset()
	tp.pendingBuffer.Reset()
	tp.thinkingStarted = false
	tp.thinkingStopped = false
	tp.textStarted = false
}

// SetThinkingStarted 标记 thinking 块已开始发送
func (tp *ThinkingParser) SetThinkingStarted() {
	tp.thinkingStarted = true
}

// IsThinkingStarted thinking 块是否已开始发送
func (tp *ThinkingParser) IsThinkingStarted() bool {
	return tp.thinkingStarted
}

// SetThinkingStopped 标记 thinking 块已结束发送
func (tp *ThinkingParser) SetThinkingStopped() {
	tp.thinkingStopped = true
}

// IsThinkingStopped thinking 块是否已结束发送
func (tp *ThinkingParser) IsThinkingStopped() bool {
	return tp.thinkingStopped
}

// SetTextStarted 标记 text 块已开始发送
func (tp *ThinkingParser) SetTextStarted() {
	tp.textStarted = true
}

// IsTextStarted text 块是否已开始发送
func (tp *ThinkingParser) IsTextStarted() bool {
	return tp.textStarted
}
