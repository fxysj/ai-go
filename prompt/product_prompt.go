package prompt

import "github.com/tmc/langchaingo/prompts"

var (
	ProductPrompt = prompts.NewPromptTemplate(`"你是产品专家，参考以下历史内容回答问题：\n{{.history}}\n用户提问：{{.input}}\n\n回答："
`, make([]string, 0))
)
