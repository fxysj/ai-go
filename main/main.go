package main

import (
	"fmt"
	"net/http"
	_ "net/http/pprof"

	"github.com/gin-gonic/gin"
)

func main() {
	// 启动 pprof，在一个 goroutine 中运行
	go func() {
		fmt.Println("pprof is running at http://localhost:6060/debug/pprof/")
		http.ListenAndServe(":6060", nil)
	}()

	// 初始化 Gin
	r := gin.Default()

	// 定义 HelloWorld 路由
	r.GET("/hello", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "Hello, world!",
		})
	})

	// 启动 Web 服务
	r.Run(":8080")
}
