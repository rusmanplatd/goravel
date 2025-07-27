package services

import (
	"encoding/json"

	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type ProjectTemplateService struct {
	auditService *AuditService
}

func NewProjectTemplateService() *ProjectTemplateService {
	return &ProjectTemplateService{
		auditService: NewAuditService(),
	}
}

// CreateTemplate creates a new project template
func (s *ProjectTemplateService) CreateTemplate(data map[string]interface{}) (*models.ProjectTemplate, error) {
	// Set default values
	if data["category"] == nil {
		data["category"] = "general"
	}
	if data["is_public"] == nil {
		data["is_public"] = false
	}
	if data["is_featured"] == nil {
		data["is_featured"] = false
	}
	if data["usage_count"] == nil {
		data["usage_count"] = 0
	}

	// Create template
	template := &models.ProjectTemplate{
		BaseModel: models.BaseModel{
			CreatedBy: data["created_by"].(*string),
		},
		Name:        data["name"].(string),
		Description: data["description"].(string),
		Category:    data["category"].(string),
		Icon:        data["icon"].(string),
		Color:       data["color"].(string),
		IsPublic:    data["is_public"].(bool),
		IsFeatured:  data["is_featured"].(bool),
		UsageCount:  data["usage_count"].(int),
	}

	// Set optional organization ID
	if orgID, exists := data["organization_id"]; exists && orgID != nil {
		orgIDStr := orgID.(string)
		template.OrganizationID = &orgIDStr
	}

	// Set configuration
	if configuration, exists := data["configuration"]; exists && configuration != nil {
		if configStr, ok := configuration.(string); ok {
			template.Configuration = configStr
		} else {
			configBytes, _ := json.Marshal(configuration)
			template.Configuration = string(configBytes)
		}
	}

	err := facades.Orm().Query().Create(template)
	if err != nil {
		return nil, err
	}

	// Log activity
	s.auditService.LogEventCompat(nil, "project_template.created", "Project template created", "", "", map[string]interface{}{
		"template_id": template.ID,
		"name":        template.Name,
		"category":    template.Category,
	}, "low")

	return template, nil
}

// GetTemplate retrieves a project template by ID
func (s *ProjectTemplateService) GetTemplate(id string) (*models.ProjectTemplate, error) {
	template := &models.ProjectTemplate{}
	err := facades.Orm().Query().Where("id = ?", id).First(template)
	if err != nil {
		return nil, err
	}
	return template, nil
}

// UpdateTemplate updates a project template
func (s *ProjectTemplateService) UpdateTemplate(id string, data map[string]interface{}) (*models.ProjectTemplate, error) {
	template, err := s.GetTemplate(id)
	if err != nil {
		return nil, err
	}

	// Update fields
	if name, exists := data["name"]; exists {
		template.Name = name.(string)
	}
	if description, exists := data["description"]; exists {
		template.Description = description.(string)
	}
	if category, exists := data["category"]; exists {
		template.Category = category.(string)
	}
	if icon, exists := data["icon"]; exists {
		template.Icon = icon.(string)
	}
	if color, exists := data["color"]; exists {
		template.Color = color.(string)
	}
	if isPublic, exists := data["is_public"]; exists {
		template.IsPublic = isPublic.(bool)
	}
	if isFeatured, exists := data["is_featured"]; exists {
		template.IsFeatured = isFeatured.(bool)
	}

	// Update configuration
	if configuration, exists := data["configuration"]; exists && configuration != nil {
		if configStr, ok := configuration.(string); ok {
			template.Configuration = configStr
		} else {
			configBytes, _ := json.Marshal(configuration)
			template.Configuration = string(configBytes)
		}
	}

	template.BaseModel.UpdatedBy = data["updated_by"].(*string)

	err = facades.Orm().Query().Save(template)
	if err != nil {
		return nil, err
	}

	// Log activity
	s.auditService.LogEventCompat(nil, "project_template.updated", "Project template updated", "", "", map[string]interface{}{
		"template_id": template.ID,
		"name":        template.Name,
		"category":    template.Category,
	}, "low")

	return template, nil
}

// DeleteTemplate deletes a project template
func (s *ProjectTemplateService) DeleteTemplate(id string, deletedBy *string) error {
	template, err := s.GetTemplate(id)
	if err != nil {
		return err
	}

	template.BaseModel.DeletedBy = deletedBy
	_, err = facades.Orm().Query().Delete(template)
	if err != nil {
		return err
	}

	// Log activity
	s.auditService.LogEventCompat(nil, "project_template.deleted", "Project template deleted", "", "", map[string]interface{}{
		"template_id": template.ID,
		"name":        template.Name,
		"category":    template.Category,
	}, "low")

	return nil
}

// ListTemplates retrieves templates with filters
func (s *ProjectTemplateService) ListTemplates(filters map[string]interface{}) ([]models.ProjectTemplate, error) {
	var templates []models.ProjectTemplate
	query := facades.Orm().Query()

	// Apply filters
	if category, exists := filters["category"]; exists {
		query = query.Where("category = ?", category)
	}
	if isPublic, exists := filters["is_public"]; exists {
		query = query.Where("is_public = ?", isPublic)
	}
	if isFeatured, exists := filters["is_featured"]; exists {
		query = query.Where("is_featured = ?", isFeatured)
	}
	if orgID, exists := filters["organization_id"]; exists {
		if orgID == nil {
			query = query.Where("organization_id IS NULL")
		} else {
			query = query.Where("organization_id = ?", orgID)
		}
	}

	err := query.OrderBy("is_featured", "DESC").OrderBy("usage_count", "DESC").OrderBy("created_at", "DESC").Find(&templates)
	if err != nil {
		return nil, err
	}

	return templates, nil
}

// UseTemplate creates a project from a template
func (s *ProjectTemplateService) UseTemplate(templateID string, projectData map[string]interface{}, createdBy *string) (*models.Project, error) {
	template, err := s.GetTemplate(templateID)
	if err != nil {
		return nil, err
	}

	// Parse template configuration
	var config map[string]interface{}
	if template.Configuration != "" {
		err = json.Unmarshal([]byte(template.Configuration), &config)
		if err != nil {
			return nil, err
		}
	}

	// Create project with template settings
	projectService := NewOrganizationService()
	project, err := projectService.CreateProject(projectData)
	if err != nil {
		return nil, err
	}

	// Apply template configuration
	if config != nil {
		err = s.applyTemplateConfiguration(project.ID, config, createdBy)
		if err != nil {
			return nil, err
		}
	}

	// Increment template usage count
	_, err = facades.Orm().Query().
		Model(&models.ProjectTemplate{}).
		Where("id = ?", templateID).
		Update("usage_count", facades.Orm().Query().Raw("usage_count + 1"))
	if err != nil {
		facades.Log().Warning("Failed to increment template usage count: " + err.Error())
	}

	// Log activity
	s.auditService.LogEventCompat(nil, "project_template.used", "Project created from template", "", "", map[string]interface{}{
		"template_id": template.ID,
		"project_id":  project.ID,
		"template":    template.Name,
		"project":     project.Name,
	}, "low")

	return project, nil
}

// applyTemplateConfiguration applies template configuration to a project
func (s *ProjectTemplateService) applyTemplateConfiguration(projectID string, config map[string]interface{}, createdBy *string) error {
	// Apply default views
	if defaultViews, exists := config["default_views"]; exists {
		viewService := NewProjectViewService()
		if views, ok := defaultViews.([]interface{}); ok {
			for i, viewData := range views {
				if viewMap, ok := viewData.(map[string]interface{}); ok {
					viewMap["project_id"] = projectID
					viewMap["created_by"] = createdBy
					viewMap["position"] = i
					if i == 0 {
						viewMap["is_default"] = true
					}
					_, err := viewService.CreateView(viewMap)
					if err != nil {
						return err
					}
				}
			}
		}
	}

	// Apply custom fields
	if customFields, exists := config["custom_fields"]; exists {
		fieldService := NewProjectCustomFieldService()
		if fields, ok := customFields.([]interface{}); ok {
			for i, fieldData := range fields {
				if fieldMap, ok := fieldData.(map[string]interface{}); ok {
					fieldMap["project_id"] = projectID
					fieldMap["created_by"] = createdBy
					fieldMap["position"] = i
					_, err := fieldService.CreateField(fieldMap)
					if err != nil {
						return err
					}
				}
			}
		}
	}

	return nil
}

// GetFeaturedTemplates gets featured templates
func (s *ProjectTemplateService) GetFeaturedTemplates() ([]models.ProjectTemplate, error) {
	return s.ListTemplates(map[string]interface{}{
		"is_featured": true,
		"is_public":   true,
	})
}

// GetTemplatesByCategory gets templates by category
func (s *ProjectTemplateService) GetTemplatesByCategory(category string) ([]models.ProjectTemplate, error) {
	return s.ListTemplates(map[string]interface{}{
		"category":  category,
		"is_public": true,
	})
}
