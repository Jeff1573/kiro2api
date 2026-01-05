package server

import (
	"testing"
)

func TestThinkingParser_BasicParsing(t *testing.T) {
	parser := NewThinkingParser()

	// 测试完整的 thinking 块
	result := parser.Parse("<thinking>这是思考内容</thinking>这是正文")

	if !result.ThinkingStart {
		t.Error("应该检测到 thinking 开始")
	}
	if !result.ThinkingEnd {
		t.Error("应该检测到 thinking 结束")
	}
	if result.ThinkingContent != "这是思考内容" {
		t.Errorf("thinking 内容不匹配: got %q, want %q", result.ThinkingContent, "这是思考内容")
	}
	if result.TextContent != "这是正文" {
		t.Errorf("正文内容不匹配: got %q, want %q", result.TextContent, "这是正文")
	}
}

func TestThinkingParser_NoThinking(t *testing.T) {
	parser := NewThinkingParser()

	// 测试没有 thinking 标签的文本
	result := parser.Parse("这是普通文本")

	if result.ThinkingStart {
		t.Error("不应该检测到 thinking 开始")
	}
	if result.ThinkingEnd {
		t.Error("不应该检测到 thinking 结束")
	}
	if result.ThinkingContent != "" {
		t.Errorf("thinking 内容应该为空: got %q", result.ThinkingContent)
	}
	if result.TextContent != "这是普通文本" {
		t.Errorf("正文内容不匹配: got %q, want %q", result.TextContent, "这是普通文本")
	}
}

func TestThinkingParser_StreamingParsing(t *testing.T) {
	parser := NewThinkingParser()

	// 模拟流式解析：标签跨分片
	result1 := parser.Parse("前缀文本<thin")
	if result1.TextContent != "前缀文本" {
		t.Errorf("第一次解析正文不匹配: got %q, want %q", result1.TextContent, "前缀文本")
	}

	result2 := parser.Parse("king>思考内容")
	if !result2.ThinkingStart {
		t.Error("应该检测到 thinking 开始")
	}
	if result2.ThinkingContent != "思考内容" {
		t.Errorf("thinking 内容不匹配: got %q, want %q", result2.ThinkingContent, "思考内容")
	}

	result3 := parser.Parse("继续思考</thinking>后续正文")
	if result3.ThinkingContent != "继续思考" {
		t.Errorf("thinking 内容不匹配: got %q, want %q", result3.ThinkingContent, "继续思考")
	}
	if !result3.ThinkingEnd {
		t.Error("应该检测到 thinking 结束")
	}
	if result3.TextContent != "后续正文" {
		t.Errorf("正文内容不匹配: got %q, want %q", result3.TextContent, "后续正文")
	}
}

func TestThinkingParser_OnlyThinking(t *testing.T) {
	parser := NewThinkingParser()

	// 测试只有 thinking 内容
	result := parser.Parse("<thinking>只有思考</thinking>")

	if !result.ThinkingStart {
		t.Error("应该检测到 thinking 开始")
	}
	if !result.ThinkingEnd {
		t.Error("应该检测到 thinking 结束")
	}
	if result.ThinkingContent != "只有思考" {
		t.Errorf("thinking 内容不匹配: got %q, want %q", result.ThinkingContent, "只有思考")
	}
	if result.TextContent != "" {
		t.Errorf("正文内容应该为空: got %q", result.TextContent)
	}
}

func TestThinkingParser_StateManagement(t *testing.T) {
	parser := NewThinkingParser()

	// 测试状态管理
	if parser.IsInThinking() {
		t.Error("初始状态不应该在 thinking 块内")
	}

	parser.Parse("<thinking>")
	if !parser.IsInThinking() {
		t.Error("解析开始标签后应该在 thinking 块内")
	}

	parser.Parse("内容</thinking>")
	if !parser.IsAfterThinking() {
		t.Error("解析结束标签后应该在 thinking 块之后")
	}
}

func TestThinkingParser_Reset(t *testing.T) {
	parser := NewThinkingParser()

	// 解析一些内容
	parser.Parse("<thinking>内容</thinking>")
	parser.SetThinkingStarted()
	parser.SetThinkingStopped()
	parser.SetTextStarted()

	// 重置
	parser.Reset()

	if parser.IsInThinking() {
		t.Error("重置后不应该在 thinking 块内")
	}
	if parser.IsAfterThinking() {
		t.Error("重置后不应该在 thinking 块之后")
	}
	if parser.IsThinkingStarted() {
		t.Error("重置后 thinking 不应该已开始")
	}
	if parser.IsThinkingStopped() {
		t.Error("重置后 thinking 不应该已结束")
	}
	if parser.IsTextStarted() {
		t.Error("重置后 text 不应该已开始")
	}
	if parser.GetThinkingContent() != "" {
		t.Error("重置后 thinking 内容应该为空")
	}
}

func TestThinkingParser_PartialTagAtEnd(t *testing.T) {
	parser := NewThinkingParser()

	// 测试部分标签在末尾的情况
	result1 := parser.Parse("文本<")
	if result1.TextContent != "文本" {
		t.Errorf("正文内容不匹配: got %q, want %q", result1.TextContent, "文本")
	}

	// 继续解析，确认不是标签
	result2 := parser.Parse("不是标签")
	if result2.TextContent != "<不是标签" {
		t.Errorf("正文内容不匹配: got %q, want %q", result2.TextContent, "<不是标签")
	}
}

func TestThinkingParser_MultipleChunks(t *testing.T) {
	parser := NewThinkingParser()

	// 模拟多个小分片
	chunks := []string{
		"<",
		"thinking",
		">",
		"思",
		"考",
		"内",
		"容",
		"</",
		"thinking",
		">",
		"正",
		"文",
	}

	var totalThinking, totalText string
	var sawStart, sawEnd bool

	for _, chunk := range chunks {
		result := parser.Parse(chunk)
		if result.ThinkingStart {
			sawStart = true
		}
		if result.ThinkingEnd {
			sawEnd = true
		}
		totalThinking += result.ThinkingContent
		totalText += result.TextContent
	}

	if !sawStart {
		t.Error("应该检测到 thinking 开始")
	}
	if !sawEnd {
		t.Error("应该检测到 thinking 结束")
	}
	if totalThinking != "思考内容" {
		t.Errorf("thinking 内容不匹配: got %q, want %q", totalThinking, "思考内容")
	}
	if totalText != "正文" {
		t.Errorf("正文内容不匹配: got %q, want %q", totalText, "正文")
	}
}
