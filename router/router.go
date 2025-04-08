package router

import (
	"github.com/gin-gonic/gin"
	"titkee.com/controller"
)

func SetupRouter() *gin.Engine {
	r := gin.Default()
	r.POST("/chat", controller.ChatHandler)
	return r
}
