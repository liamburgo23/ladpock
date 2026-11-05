package main

import "github.com/gin-gonic/gin"

func routes(r *gin.Engine) {
	api := r.Group("/api")
	api.POST("/orders", createOrder)
	me := api.Group("/me", requireAuth())
	me.GET("/orders/:id", getOrder)
}

func createOrder(c *gin.Context) {
	db.Exec("INSERT INTO orders (total) VALUES (?)", c.PostForm("total"))
}

func getOrder(c *gin.Context) {
	var order Order
	db.First(&order, c.Param("id"))
	c.JSON(200, order)
}
