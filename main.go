package main

import (
	"titkee.com/router"
	"titkee.com/util"
)

func main() {
	util.LoadEnv() // 加载 .env
	r := router.SetupRouter()
	r.Run(":8080")
}
