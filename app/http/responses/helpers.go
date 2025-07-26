package responses

import (
	"time"

	"goravel/app/querybuilder"

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

// QueryBuilderSuccessResponse creates a successful response from QueryBuilder result
func QueryBuilderSuccessResponse(ctx http.Context, message string, result *querybuilder.UnifiedPaginationResult) http.Response {
	// Convert querybuilder.PaginationInfo to responses.PaginationInfo
	var pagination *PaginationInfo
	if result.Pagination != nil {
		pagination = &PaginationInfo{
			Type:        result.Pagination.Type,
			Count:       result.Pagination.Count,
			Limit:       result.Pagination.Limit,
			HasNext:     result.Pagination.HasNext,
			HasPrev:     result.Pagination.HasPrev,
			CurrentPage: result.Pagination.CurrentPage,
			LastPage:    result.Pagination.LastPage,
			PerPage:     result.Pagination.PerPage,
			Total:       result.Pagination.Total,
			From:        result.Pagination.From,
			To:          result.Pagination.To,
			NextCursor:  result.Pagination.NextCursor,
			PrevCursor:  result.Pagination.PrevCursor,
		}
	}

	response := QueryBuilderResponse{
		Status:     "success",
		Message:    message,
		Data:       result.Data,
		Pagination: pagination,
		Timestamp:  time.Now(),
	}
	return ctx.Response().Json(200, response)
}

// PaginatedSuccessResponse creates a successful paginated response
func PaginatedSuccessResponse(ctx http.Context, message string, data interface{}, pagination PaginationInfo) http.Response {
	response := PaginatedResponse{
		Status:     "success",
		Message:    message,
		Data:       data,
		Pagination: pagination,
		Timestamp:  time.Now(),
	}
	return ctx.Response().Json(200, response)
}
