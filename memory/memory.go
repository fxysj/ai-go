package memory

import "github.com/tmc/langchaingo/memory"

var _ memory.ChatMessageHistory = memory.ChatMessageHistory{} // 验证类型是否实现接口

// NewSimpleMemory 返回一个类型为 memory.ChatMessageHistory 的 Simple 实现
func NewSimpleMemory() *memory.ChatMessageHistory {
	return memory.NewChatMessageHistory() // 返回 Simple 类型，符合 ChatMessageHistory 接口
}
