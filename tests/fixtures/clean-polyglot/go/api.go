package main

import "github.com/gin-gonic/gin"

func routes(r *gin.Engine) {
	api := r.Group("/api", requireAuth())
	api.POST("/orders", createOrder)
	api.GET("/orders/:id", getOrder)
}

func createOrder(c *gin.Context) {
	var input OrderInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.AbortWithStatus(400)
		return
	}
	userID := c.GetString("userID")
	db.Exec("INSERT INTO orders (total, user_id) VALUES (?, ?)", input.Total, userID)
}

func getOrder(c *gin.Context) {
	var order Order
	userID := c.GetString("userID")
	db.Where("user_id = ?", userID).First(&order, c.Param("id"))
	c.JSON(200, order)
}
