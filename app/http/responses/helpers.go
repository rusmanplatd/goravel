package responses

import (
	"time"

	"github.com/goravel/framework/contracts/http"
)

// SuccessResponse creates a successful API response
func SuccessResponse(ctx http.Context, message string, data interface{}) http.Response {
	response := APIResponse{
		Status:    "success",
		Message:   message,
		Data:      data,
		Timestamp: time.Now(),
	}
	return ctx.Response().Json(200, response)
}

// CreateErrorResponse creates an error API response
func CreateErrorResponse(ctx http.Context, message string, details string, statusCode int) http.Response {
	response := ErrorResponse{
		Status:    "error",
		Message:   message,
		Details:   details,
		Timestamp: time.Now(),
	}
	return ctx.Response().Status(statusCode).Json(response)
}
