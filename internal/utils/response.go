package utils

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type ResponseHelper struct {
	c *gin.Context
}

func NewResponseHelper(c *gin.Context) *ResponseHelper {
	return &ResponseHelper{c: c}
}

func (r *ResponseHelper) Success(data interface{}, message ...string) {
	msg := "Success"
	if len(message) > 0 {
		msg = message[0]
	}

	r.c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": msg,
		"data":    data,
	})
}

func (r *ResponseHelper) BadRequest(message string, details ...string) {
	response := gin.H{
		"success": false,
		"message": message,
	}
	
	if len(details) > 0 {
		response["details"] = details[0]
	}

	r.c.JSON(http.StatusBadRequest, response)
}

func (r *ResponseHelper) Unauthorized(message string) {
	r.c.JSON(http.StatusUnauthorized, gin.H{
		"success": false,
		"message": message,
	})
}

func (r *ResponseHelper) Forbidden(message string) {
	r.c.JSON(http.StatusForbidden, gin.H{
		"success": false,
		"message": message,
	})
}

func (r *ResponseHelper) NotFound(message string) {
	r.c.JSON(http.StatusNotFound, gin.H{
		"success": false,
		"message": message,
	})
}

func (r *ResponseHelper) Conflict(message string) {
	r.c.JSON(http.StatusConflict, gin.H{
		"success": false,
		"message": message,
	})
}

func (r *ResponseHelper) InternalError(message string) {
	r.c.JSON(http.StatusInternalServerError, gin.H{
		"success": false,
		"message": message,
	})
}