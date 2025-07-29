package v1

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	nethttp "net/http"
	"strings"
	"time"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/http/requests"
	"goravel/app/http/responses"
	"goravel/app/models"
	"goravel/app/querybuilder"
)

type ProjectWebhooksController struct{}

func NewProjectWebhooksController() *ProjectWebhooksController {
	return &ProjectWebhooksController{}
}

// ListWebhooks lists all webhooks for a project
// @Summary List project webhooks
// @Description Get all webhooks configured for a project (GitHub Projects v2 style)
// @Tags project-webhooks
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param per_page query int false "Results per page" minimum(1) maximum(100) default(30)
// @Param page query int false "Page number" minimum(1) default(1)
// @Success 200 {array} models.ProjectWebhook
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/webhooks [get]
func (pwc *ProjectWebhooksController) ListWebhooks(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	userID := ctx.Value("user_id").(string)

	// Verify project exists and user has admin permission
	if !pwc.canManageWebhooks(userID, projectID) {
		return ctx.Response().Status(403).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Insufficient permissions to view project webhooks",
			Timestamp: time.Now(),
		})
	}

	var webhooks []models.ProjectWebhook

	query := querybuilder.For(&models.ProjectWebhook{}).
		WithRequest(ctx).
		AllowedFilters(
			querybuilder.Exact("is_active"),
			querybuilder.Exact("event_type"),
			querybuilder.Partial("name"),
		).
		AllowedSorts("name", "created_at", "updated_at", "last_triggered_at").
		DefaultSort("-created_at").
		Build().
		Where("project_id = ?", projectID)

	qb := querybuilder.For(query).WithRequest(ctx)
	result, err := qb.AutoPaginate(&webhooks)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve project webhooks: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return responses.QueryBuilderSuccessResponse(ctx, "Project webhooks retrieved successfully", result)
}

// CreateWebhook creates a new webhook for a project
// @Summary Create project webhook
// @Description Create a new webhook for project events (GitHub Projects v2 style)
// @Tags project-webhooks
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param request body requests.ProjectWebhookRequest true "Webhook data"
// @Success 201 {object} models.ProjectWebhook
// @Failure 400 {object} responses.ErrorResponse
// @Router /projects/{project_id}/webhooks [post]
func (pwc *ProjectWebhooksController) CreateWebhook(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	userID := ctx.Value("user_id").(string)

	// Verify project exists and user has admin permission
	if !pwc.canManageWebhooks(userID, projectID) {
		return ctx.Response().Status(403).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Insufficient permissions to create project webhooks",
			Timestamp: time.Now(),
		})
	}

	var request requests.ProjectWebhookRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(422).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Validation failed: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Generate secret for webhook signing
	secret, err := pwc.generateWebhookSecret()
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to generate webhook secret: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Create webhook
	webhook := models.ProjectWebhook{
		ProjectID:   projectID,
		Name:        request.Name,
		URL:         request.URL,
		Secret:      secret,
		Events:      request.Events,
		ContentType: request.ContentType,
		IsActive:    request.IsActive,
		Description: request.Description,
	}

	if err := facades.Orm().Query().Create(&webhook); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to create project webhook: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Create activity log
	activity := models.ActivityLog{
		LogName:     "webhook_created",
		Description: "Webhook '" + webhook.Name + "' was created for URL: " + webhook.URL,
		Category:    models.CategorySystem,
		Severity:    models.SeverityInfo,
		SubjectID:   projectID,
		SubjectType: "Project",
		CauserID:    userID,
		CauserType:  "User",
	}
	facades.Orm().Query().Create(&activity)

	return ctx.Response().Status(201).Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project webhook created successfully",
		Data:      webhook,
		Timestamp: time.Now(),
	})
}

// GetWebhook retrieves a specific webhook
// @Summary Get project webhook
// @Description Get a specific project webhook by ID
// @Tags project-webhooks
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param webhook_id path string true "Webhook ID"
// @Success 200 {object} models.ProjectWebhook
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/webhooks/{webhook_id} [get]
func (pwc *ProjectWebhooksController) GetWebhook(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	webhookID := ctx.Request().Route("webhook_id")
	userID := ctx.Value("user_id").(string)

	// Verify project exists and user has admin permission
	if !pwc.canManageWebhooks(userID, projectID) {
		return ctx.Response().Status(403).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Insufficient permissions to view project webhooks",
			Timestamp: time.Now(),
		})
	}

	var webhook models.ProjectWebhook
	if err := facades.Orm().Query().
		Where("id = ? AND project_id = ?", webhookID, projectID).
		First(&webhook); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project webhook not found",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project webhook retrieved successfully",
		Data:      webhook,
		Timestamp: time.Now(),
	})
}

// UpdateWebhook updates a project webhook
// @Summary Update project webhook
// @Description Update an existing project webhook
// @Tags project-webhooks
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param webhook_id path string true "Webhook ID"
// @Param request body requests.ProjectWebhookUpdateRequest true "Webhook update data"
// @Success 200 {object} models.ProjectWebhook
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/webhooks/{webhook_id} [patch]
func (pwc *ProjectWebhooksController) UpdateWebhook(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	webhookID := ctx.Request().Route("webhook_id")
	userID := ctx.Value("user_id").(string)

	// Verify project exists and user has admin permission
	if !pwc.canManageWebhooks(userID, projectID) {
		return ctx.Response().Status(403).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Insufficient permissions to update project webhooks",
			Timestamp: time.Now(),
		})
	}

	var webhook models.ProjectWebhook
	if err := facades.Orm().Query().
		Where("id = ? AND project_id = ?", webhookID, projectID).
		First(&webhook); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project webhook not found",
			Timestamp: time.Now(),
		})
	}

	var request requests.ProjectWebhookUpdateRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(422).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Validation failed: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Update webhook fields
	if request.Name != "" {
		webhook.Name = request.Name
	}
	if request.URL != "" {
		webhook.URL = request.URL
	}
	if len(request.Events) > 0 {
		webhook.Events = request.Events
	}
	if request.ContentType != "" {
		webhook.ContentType = request.ContentType
	}
	if request.Description != nil {
		webhook.Description = *request.Description
	}
	if request.IsActive != nil {
		webhook.IsActive = *request.IsActive
	}

	// Regenerate secret if requested
	if request.RegenerateSecret {
		secret, err := pwc.generateWebhookSecret()
		if err != nil {
			return ctx.Response().Status(500).Json(responses.ErrorResponse{
				Status:    "error",
				Message:   "Failed to regenerate webhook secret: " + err.Error(),
				Timestamp: time.Now(),
			})
		}
		webhook.Secret = secret
	}

	if err := facades.Orm().Query().Save(&webhook); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to update project webhook: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Create activity log
	activity := models.ActivityLog{
		LogName:     "webhook_updated",
		Description: "Webhook '" + webhook.Name + "' was updated",
		Category:    models.CategorySystem,
		Severity:    models.SeverityInfo,
		SubjectID:   projectID,
		SubjectType: "Project",
		CauserID:    userID,
		CauserType:  "User",
	}
	facades.Orm().Query().Create(&activity)

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project webhook updated successfully",
		Data:      webhook,
		Timestamp: time.Now(),
	})
}

// DeleteWebhook deletes a project webhook
// @Summary Delete project webhook
// @Description Delete a project webhook
// @Tags project-webhooks
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param webhook_id path string true "Webhook ID"
// @Success 204
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/webhooks/{webhook_id} [delete]
func (pwc *ProjectWebhooksController) DeleteWebhook(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	webhookID := ctx.Request().Route("webhook_id")
	userID := ctx.Value("user_id").(string)

	// Verify project exists and user has admin permission
	if !pwc.canManageWebhooks(userID, projectID) {
		return ctx.Response().Status(403).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Insufficient permissions to delete project webhooks",
			Timestamp: time.Now(),
		})
	}

	var webhook models.ProjectWebhook
	if err := facades.Orm().Query().
		Where("id = ? AND project_id = ?", webhookID, projectID).
		First(&webhook); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project webhook not found",
			Timestamp: time.Now(),
		})
	}

	if _, err := facades.Orm().Query().Delete(&webhook); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to delete project webhook: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Create activity log
	activity := models.ActivityLog{
		LogName:     "webhook_deleted",
		Description: "Webhook '" + webhook.Name + "' was deleted",
		Category:    models.CategorySystem,
		Severity:    models.SeverityInfo,
		SubjectID:   projectID,
		SubjectType: "Project",
		CauserID:    userID,
		CauserType:  "User",
	}
	facades.Orm().Query().Create(&activity)

	return ctx.Response().Status(204).Json(nil)
}

// TestWebhook sends a test payload to a webhook
// @Summary Test project webhook
// @Description Send a test payload to verify webhook configuration
// @Tags project-webhooks
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param webhook_id path string true "Webhook ID"
// @Success 200 {object} responses.APIResponse
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/webhooks/{webhook_id}/test [post]
func (pwc *ProjectWebhooksController) TestWebhook(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	webhookID := ctx.Request().Route("webhook_id")
	userID := ctx.Value("user_id").(string)

	// Verify project exists and user has admin permission
	if !pwc.canManageWebhooks(userID, projectID) {
		return ctx.Response().Status(403).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Insufficient permissions to test project webhooks",
			Timestamp: time.Now(),
		})
	}

	var webhook models.ProjectWebhook
	if err := facades.Orm().Query().
		Where("id = ? AND project_id = ?", webhookID, projectID).
		First(&webhook); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project webhook not found",
			Timestamp: time.Now(),
		})
	}

	// Create test payload
	testPayload := map[string]interface{}{
		"event":      "ping",
		"action":     "test",
		"project_id": projectID,
		"webhook": map[string]interface{}{
			"id":   webhook.ID,
			"name": webhook.Name,
			"url":  webhook.URL,
		},
		"sender": map[string]interface{}{
			"id":   userID,
			"type": "user",
		},
		"timestamp": time.Now().Format(time.RFC3339),
		"test":      true,
	}

	// Send webhook
	delivery, err := pwc.sendWebhook(webhook, testPayload)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to send test webhook: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:  "success",
		Message: "Test webhook sent successfully",
		Data: map[string]interface{}{
			"delivery_id":   delivery.ID,
			"status_code":   delivery.StatusCode,
			"response_time": delivery.ResponseTime,
			"success":       delivery.Success,
			"error_message": delivery.ErrorMessage,
		},
		Timestamp: time.Now(),
	})
}

// GetWebhookDeliveries gets delivery history for a webhook
// @Summary Get webhook deliveries
// @Description Get delivery history and logs for a project webhook
// @Tags project-webhooks
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param webhook_id path string true "Webhook ID"
// @Param per_page query int false "Results per page" minimum(1) maximum(100) default(30)
// @Param page query int false "Page number" minimum(1) default(1)
// @Success 200 {array} models.WebhookDelivery
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/webhooks/{webhook_id}/deliveries [get]
func (pwc *ProjectWebhooksController) GetWebhookDeliveries(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	webhookID := ctx.Request().Route("webhook_id")
	userID := ctx.Value("user_id").(string)

	// Verify project exists and user has admin permission
	if !pwc.canManageWebhooks(userID, projectID) {
		return ctx.Response().Status(403).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Insufficient permissions to view webhook deliveries",
			Timestamp: time.Now(),
		})
	}

	// Verify webhook exists
	var webhook models.ProjectWebhook
	if err := facades.Orm().Query().
		Where("id = ? AND project_id = ?", webhookID, projectID).
		First(&webhook); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project webhook not found",
			Timestamp: time.Now(),
		})
	}

	var deliveries []models.WebhookDelivery

	query := querybuilder.For(&models.WebhookDelivery{}).
		WithRequest(ctx).
		AllowedFilters(
			querybuilder.Exact("success"),
			querybuilder.Exact("event_type"),
			querybuilder.Partial("status_code"),
		).
		AllowedSorts("created_at", "status_code", "response_time").
		DefaultSort("-created_at").
		Build().
		Where("webhook_id = ?", webhookID)

	qb := querybuilder.For(query).WithRequest(ctx)
	result, err := qb.AutoPaginate(&deliveries)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve webhook deliveries: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return responses.QueryBuilderSuccessResponse(ctx, "Webhook deliveries retrieved successfully", result)
}

// RedeliverWebhook redelivers a failed webhook
// @Summary Redeliver webhook
// @Description Redeliver a failed webhook delivery
// @Tags project-webhooks
// @Accept json
// @Produce json
// @Param project_id path string true "Project ID"
// @Param webhook_id path string true "Webhook ID"
// @Param delivery_id path string true "Delivery ID"
// @Success 200 {object} responses.APIResponse
// @Failure 404 {object} responses.ErrorResponse
// @Router /projects/{project_id}/webhooks/{webhook_id}/deliveries/{delivery_id}/redeliver [post]
func (pwc *ProjectWebhooksController) RedeliverWebhook(ctx http.Context) http.Response {
	projectID := ctx.Request().Route("project_id")
	webhookID := ctx.Request().Route("webhook_id")
	deliveryID := ctx.Request().Route("delivery_id")
	userID := ctx.Value("user_id").(string)

	// Verify project exists and user has admin permission
	if !pwc.canManageWebhooks(userID, projectID) {
		return ctx.Response().Status(403).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Insufficient permissions to redeliver webhooks",
			Timestamp: time.Now(),
		})
	}

	// Get webhook and original delivery
	var webhook models.ProjectWebhook
	if err := facades.Orm().Query().
		Where("id = ? AND project_id = ?", webhookID, projectID).
		First(&webhook); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Project webhook not found",
			Timestamp: time.Now(),
		})
	}

	var originalDelivery models.WebhookDelivery
	if err := facades.Orm().Query().
		Where("id = ? AND webhook_id = ?", deliveryID, webhookID).
		First(&originalDelivery); err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Webhook delivery not found",
			Timestamp: time.Now(),
		})
	}

	// Parse original payload
	var payload map[string]interface{}
	if err := json.Unmarshal(originalDelivery.Payload, &payload); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to parse original payload: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Add redelivery information
	payload["redelivery"] = true
	payload["original_delivery_id"] = originalDelivery.ID
	payload["redelivered_at"] = time.Now().Format(time.RFC3339)

	// Send webhook
	newDelivery, err := pwc.sendWebhook(webhook, payload)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to redeliver webhook: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:  "success",
		Message: "Webhook redelivered successfully",
		Data: map[string]interface{}{
			"original_delivery_id": originalDelivery.ID,
			"new_delivery_id":      newDelivery.ID,
			"status_code":          newDelivery.StatusCode,
			"success":              newDelivery.Success,
		},
		Timestamp: time.Now(),
	})
}

// Helper methods

func (pwc *ProjectWebhooksController) canManageWebhooks(userID, projectID string) bool {
	// Check if user is project owner
	var project models.Project
	if err := facades.Orm().Query().Where("id = ? AND owner_id = ?", projectID, userID).First(&project); err == nil {
		return true
	}

	// Check if user is organization admin
	if err := facades.Orm().Query().Raw(`
		SELECT 1 FROM user_organizations uo
		JOIN projects p ON uo.organization_id = p.organization_id
		WHERE p.id = ? AND uo.user_id = ? AND uo.role IN ('admin', 'owner') AND uo.is_active = true
	`, projectID, userID).First(&struct{}{}); err == nil {
		return true
	}

	return false
}

func (pwc *ProjectWebhooksController) generateWebhookSecret() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func (pwc *ProjectWebhooksController) sendWebhook(webhook models.ProjectWebhook, payload map[string]interface{}) (*models.WebhookDelivery, error) {
	// Convert payload to JSON
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Create signature
	signature := pwc.createSignature(payloadBytes, webhook.Secret)

	// Create delivery record
	delivery := models.WebhookDelivery{
		WebhookID: webhook.ID,
		EventType: fmt.Sprintf("%v", payload["event"]),
		Payload:   payloadBytes,
		Signature: signature,
	}

	startTime := time.Now()

	// Create HTTP client with timeout
	client := &nethttp.Client{
		Timeout: 30 * time.Second,
	}

	// Create request
	req, err := nethttp.NewRequest("POST", webhook.URL, strings.NewReader(string(payloadBytes)))
	if err != nil {
		delivery.Success = false
		delivery.ErrorMessage = err.Error()
		delivery.ResponseTime = int(time.Since(startTime).Milliseconds())
		facades.Orm().Query().Create(&delivery)
		return &delivery, err
	}

	// Set headers
	req.Header.Set("Content-Type", webhook.ContentType)
	req.Header.Set("User-Agent", "Goravel-Webhooks/1.0")
	req.Header.Set("X-Webhook-Signature", signature)
	req.Header.Set("X-Webhook-Event", delivery.EventType)
	req.Header.Set("X-Webhook-Delivery", delivery.ID)

	// Send request
	resp, err := client.Do(req)
	delivery.ResponseTime = int(time.Since(startTime).Milliseconds())

	if err != nil {
		delivery.Success = false
		delivery.ErrorMessage = err.Error()
		delivery.StatusCode = 0
	} else {
		delivery.StatusCode = resp.StatusCode
		delivery.Success = resp.StatusCode >= 200 && resp.StatusCode < 300
		if !delivery.Success {
			delivery.ErrorMessage = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		resp.Body.Close()
	}

	// Update webhook last triggered time
	webhook.LastTriggeredAt = &startTime
	webhook.DeliveryCount++
	if delivery.Success {
		webhook.SuccessCount++
	} else {
		webhook.FailureCount++
	}
	facades.Orm().Query().Save(&webhook)

	// Save delivery record
	if err := facades.Orm().Query().Create(&delivery); err != nil {
		return nil, fmt.Errorf("failed to save delivery record: %w", err)
	}

	return &delivery, nil
}

func (pwc *ProjectWebhooksController) createSignature(payload []byte, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write(payload)
	return "sha256=" + hex.EncodeToString(h.Sum(nil))
}

// TriggerWebhook triggers webhooks for a project event (called internally)
func (pwc *ProjectWebhooksController) TriggerWebhook(projectID, eventType string, payload map[string]interface{}) {
	// Get active webhooks for this project and event type
	var webhooks []models.ProjectWebhook
	facades.Orm().Query().
		Where("project_id = ? AND is_active = true", projectID).
		Find(&webhooks)

	for _, webhook := range webhooks {
		// Check if webhook is configured for this event type
		eventConfigured := false
		for _, event := range webhook.Events {
			if event == eventType || event == "*" {
				eventConfigured = true
				break
			}
		}

		if !eventConfigured {
			continue
		}

		// Add webhook metadata to payload
		payload["webhook_id"] = webhook.ID
		payload["event"] = eventType
		payload["timestamp"] = time.Now().Format(time.RFC3339)

		// Send webhook asynchronously
		go func(w models.ProjectWebhook, p map[string]interface{}) {
			_, err := pwc.sendWebhook(w, p)
			if err != nil {
				facades.Log().Error("Failed to send webhook", map[string]interface{}{
					"webhook_id": w.ID,
					"project_id": projectID,
					"event":      eventType,
					"error":      err.Error(),
				})
			}
		}(webhook, payload)
	}
}
