package responses

import (
	"net/url"
	"strings"
	"time"

	"goravel/app/querybuilder"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"
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

// Success creates a successful API response (alias for SuccessResponse)
func Success(ctx http.Context, message string, data interface{}) http.Response {
	return SuccessResponse(ctx, message, data)
}

// Created creates a 201 Created response
func Created(ctx http.Context, message string, data interface{}) http.Response {
	response := APIResponse{
		Status:    "success",
		Message:   message,
		Data:      data,
		Timestamp: time.Now(),
	}
	return ctx.Response().Json(201, response)
}

// BadRequest creates a 400 Bad Request response
func BadRequest(ctx http.Context, message string, details interface{}) http.Response {
	response := ErrorResponse{
		Status:    "error",
		Message:   message,
		Details:   details,
		Timestamp: time.Now(),
	}
	return ctx.Response().Json(400, response)
}

// NotFound creates a 404 Not Found response
func NotFound(ctx http.Context, message string, details interface{}) http.Response {
	response := ErrorResponse{
		Status:    "error",
		Message:   message,
		Details:   details,
		Timestamp: time.Now(),
	}
	return ctx.Response().Json(404, response)
}

// Forbidden creates a 403 Forbidden response
func Forbidden(ctx http.Context, message string, details interface{}) http.Response {
	response := ErrorResponse{
		Status:    "error",
		Message:   message,
		Details:   details,
		Timestamp: time.Now(),
	}
	return ctx.Response().Json(403, response)
}

// InternalServerError creates a 500 Internal Server Error response
func InternalServerError(ctx http.Context, message string, details interface{}) http.Response {
	response := ErrorResponse{
		Status:    "error",
		Message:   message,
		Details:   details,
		Timestamp: time.Now(),
	}
	return ctx.Response().Json(500, response)
}

// PaginatedSuccess creates a successful paginated response
func PaginatedSuccess(ctx http.Context, message string, data interface{}, total int64, page, limit int) http.Response {
	// Calculate pagination info
	totalPages := int((total + int64(limit) - 1) / int64(limit))
	from := (page-1)*limit + 1
	to := page * limit
	if int64(to) > total {
		to = int(total)
	}
	if total == 0 {
		from = 0
		to = 0
	}

	pagination := PaginationInfo{
		Type:        "offset",
		Count:       len(data.([]interface{})),
		Limit:       limit,
		HasNext:     page < totalPages,
		HasPrev:     page > 1,
		CurrentPage: &page,
		LastPage:    &totalPages,
		PerPage:     &limit,
		Total:       &total,
		From:        &from,
		To:          &to,
	}

	response := PaginatedResponse{
		Status:     "success",
		Message:    message,
		Data:       data,
		Pagination: pagination,
		Timestamp:  time.Now(),
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

// OAuth2ErrorResponse creates a standardized OAuth2 error response
func OAuth2ErrorResponse(ctx http.Context, errorCode, errorDescription string, statusCode int) http.Response {
	errorResponse := map[string]interface{}{
		"error":             errorCode,
		"error_description": errorDescription,
	}

	// Add error URI for documentation if available
	if errorCode != "" {
		baseURL := facades.Config().GetString("app.url", "")
		if baseURL != "" {
			errorResponse["error_uri"] = baseURL + "/docs/oauth2/errors#" + errorCode
		}
	}

	return ctx.Response().Json(statusCode, errorResponse)
}

// OAuth2RedirectErrorResponse creates an OAuth2 error response for redirect scenarios
func OAuth2RedirectErrorResponse(redirectURI, errorCode, errorDescription, state string) string {
	params := url.Values{}
	params.Set("error", errorCode)
	params.Set("error_description", errorDescription)

	if state != "" {
		params.Set("state", state)
	}

	if strings.Contains(redirectURI, "?") {
		return redirectURI + "&" + params.Encode()
	}
	return redirectURI + "?" + params.Encode()
}

// OIDCErrorResponse creates an OpenID Connect specific error response
func OIDCErrorResponse(ctx http.Context, errorCode, errorDescription string, statusCode int) http.Response {
	errorResponse := map[string]interface{}{
		"error":             errorCode,
		"error_description": errorDescription,
	}

	// Add OIDC specific fields
	switch errorCode {
	case "invalid_request":
		errorResponse["error_uri"] = facades.Config().GetString("app.url", "") + "/docs/oidc/errors#invalid_request"
	case "unauthorized_client":
		errorResponse["error_uri"] = facades.Config().GetString("app.url", "") + "/docs/oidc/errors#unauthorized_client"
	case "access_denied":
		errorResponse["error_uri"] = facades.Config().GetString("app.url", "") + "/docs/oidc/errors#access_denied"
	case "unsupported_response_type":
		errorResponse["error_uri"] = facades.Config().GetString("app.url", "") + "/docs/oidc/errors#unsupported_response_type"
	case "invalid_scope":
		errorResponse["error_uri"] = facades.Config().GetString("app.url", "") + "/docs/oidc/errors#invalid_scope"
	case "server_error":
		errorResponse["error_uri"] = facades.Config().GetString("app.url", "") + "/docs/oidc/errors#server_error"
	case "temporarily_unavailable":
		errorResponse["error_uri"] = facades.Config().GetString("app.url", "") + "/docs/oidc/errors#temporarily_unavailable"
	}

	return ctx.Response().Json(statusCode, errorResponse)
}

// TokenErrorResponse creates a token endpoint specific error response
func TokenErrorResponse(ctx http.Context, errorCode, errorDescription string) http.Response {
	statusCode := 400

	// Map specific error codes to appropriate HTTP status codes
	switch errorCode {
	case "invalid_client":
		statusCode = 401
	case "invalid_grant":
		statusCode = 400
	case "unauthorized_client":
		statusCode = 401
	case "unsupported_grant_type":
		statusCode = 400
	case "invalid_scope":
		statusCode = 400
	case "server_error":
		statusCode = 500
	case "temporarily_unavailable":
		statusCode = 503
	}

	return OAuth2ErrorResponse(ctx, errorCode, errorDescription, statusCode)
}

// UserInfoErrorResponse creates a UserInfo endpoint specific error response
func UserInfoErrorResponse(ctx http.Context, errorCode, errorDescription string) http.Response {
	statusCode := 400

	// Map specific error codes to appropriate HTTP status codes
	switch errorCode {
	case "invalid_token":
		statusCode = 401
		ctx.Response().Header("WWW-Authenticate", `Bearer error="invalid_token", error_description="`+errorDescription+`"`)
	case "insufficient_scope":
		statusCode = 403
		ctx.Response().Header("WWW-Authenticate", `Bearer error="insufficient_scope", error_description="`+errorDescription+`"`)
	}

	return OAuth2ErrorResponse(ctx, errorCode, errorDescription, statusCode)
}

// IntrospectionErrorResponse creates a token introspection specific error response
func IntrospectionErrorResponse(ctx http.Context, errorCode, errorDescription string) http.Response {
	// Token introspection errors are typically returned as 200 OK with active: false
	// But authentication errors should return appropriate HTTP status codes
	if errorCode == "invalid_client" {
		return OAuth2ErrorResponse(ctx, errorCode, errorDescription, 401)
	}

	// For invalid tokens, return inactive response
	if errorCode == "invalid_token" {
		return ctx.Response().Json(200, map[string]interface{}{
			"active": false,
		})
	}

	return OAuth2ErrorResponse(ctx, errorCode, errorDescription, 400)
}
