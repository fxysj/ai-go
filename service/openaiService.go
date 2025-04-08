package service

import (
	"context"
	"errors"
	"github.com/tmc/langchaingo/chains"
	"github.com/tmc/langchaingo/llms/openai"
	"os"
	"strings"
	"titkee.com/memory"
	"titkee.com/prompt"
)

func AskOpenAI(ctx context.Context, question string) (string, error) {
	llm, err := openai.New(
		openai.WithModel("gpt-4o"),
		openai.WithToken(os.Getenv("OPENAI_API_KEY")),
		openai.WithBaseURL(os.Getenv("OPENAI_API_BASE_URL")),
	)
	if err != nil {
		return "", err
	}
	mem := memory.NewSimpleMemory()
	// 模拟历史记录拼接逻辑
	historyMsgs, _ := mem.Messages(ctx)
	var historyBuilder strings.Builder
	for _, msg := range historyMsgs {
		historyBuilder.WriteString(msg.GetContent())
		historyBuilder.WriteString("\n")
	}
	history := historyBuilder.String()
	println(history)
	if err != nil {
		return "", err
	}
	chain := chains.NewLLMChain(llm, prompt.ProductPrompt)
	res, err := chain.Call(ctx, map[string]any{
		"input":   question,
		"history": history,
	})
	if err != nil {
		return "", err
	}

	output, ok := res["text"].(string)
	if !ok {
		return "", errors.New("invalid response type")
	}
	return output, nil
}
