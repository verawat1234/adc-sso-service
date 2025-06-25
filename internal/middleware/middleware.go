package middleware

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

func Logger() gin.HandlerFunc {
	return gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		logrus.WithFields(logrus.Fields{
			"status":      param.StatusCode,
			"method":      param.Method,
			"path":        param.Path,
			"ip":          param.ClientIP,
			"latency":     param.Latency,
			"user_agent":  param.Request.UserAgent(),
			"time":        param.TimeStamp.Format(time.RFC3339),
		}).Info("Request processed")
		return ""
	})
}

func Recovery() gin.HandlerFunc {
	return gin.CustomRecovery(func(c *gin.Context, recovered interface{}) {
		logrus.WithField("error", recovered).Error("Panic recovered")
		c.JSON(500, gin.H{
			"success": false,
			"message": "Internal server error",
		})
		c.Abort()
	})
}