package services

import (
	"encoding/json"
	"errors"

	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type ProjectViewService struct {
	auditService *AuditService
}

func NewProjectViewService() *ProjectViewService {
	return &ProjectViewService{
		auditService: NewAuditService(),
	}
}

// CreateView creates a new project view
func (s *ProjectViewService) CreateView(data map[string]interface{}) (*models.ProjectView, error) {
	// Set default values
	if data["is_default"] == nil {
		data["is_default"] = false
	}
	if data["is_public"] == nil {
		data["is_public"] = true
	}
	if data["position"] == nil {
		data["position"] = 0
	}

	// Create view
	view := &models.ProjectView{
		BaseModel: models.BaseModel{
			CreatedBy: data["created_by"].(*string),
		},
		Name:        data["name"].(string),
		Description: data["description"].(string),
		Type:        data["type"].(string),
		IsDefault:   data["is_default"].(bool),
		IsPublic:    data["is_public"].(bool),
		Position:    data["position"].(int),
		ProjectID:   data["project_id"].(string),
	}

	// Set optional JSON fields
	if layout, exists := data["layout"]; exists && layout != nil {
		if layoutStr, ok := layout.(string); ok {
			view.Layout = layoutStr
		} else {
			layoutBytes, _ := json.Marshal(layout)
			view.Layout = string(layoutBytes)
		}
	}

	if filters, exists := data["filters"]; exists && filters != nil {
		if filtersStr, ok := filters.(string); ok {
			view.Filters = filtersStr
		} else {
			filtersBytes, _ := json.Marshal(filters)
			view.Filters = string(filtersBytes)
		}
	}

	if sorting, exists := data["sorting"]; exists && sorting != nil {
		if sortingStr, ok := sorting.(string); ok {
			view.Sorting = sortingStr
		} else {
			sortingBytes, _ := json.Marshal(sorting)
			view.Sorting = string(sortingBytes)
		}
	}

	if grouping, exists := data["grouping"]; exists && grouping != nil {
		if groupingStr, ok := grouping.(string); ok {
			view.Grouping = groupingStr
		} else {
			groupingBytes, _ := json.Marshal(grouping)
			view.Grouping = string(groupingBytes)
		}
	}

	err := facades.Orm().Query().Create(view)
	if err != nil {
		return nil, err
	}

	// Log activity
	s.auditService.LogEventCompat(nil, "project_view.created", "Project view created", "", "", map[string]interface{}{
		"view_id":    view.ID,
		"name":       view.Name,
		"type":       view.Type,
		"project_id": view.ProjectID,
	}, "low")

	return view, nil
}

// GetView retrieves a project view by ID
func (s *ProjectViewService) GetView(id string) (*models.ProjectView, error) {
	view := &models.ProjectView{}
	err := facades.Orm().Query().Where("id = ?", id).First(view)
	if err != nil {
		return nil, err
	}
	return view, nil
}

// UpdateView updates a project view
func (s *ProjectViewService) UpdateView(id string, data map[string]interface{}) (*models.ProjectView, error) {
	view, err := s.GetView(id)
	if err != nil {
		return nil, err
	}

	// Update fields
	if name, exists := data["name"]; exists {
		view.Name = name.(string)
	}
	if description, exists := data["description"]; exists {
		view.Description = description.(string)
	}
	if viewType, exists := data["type"]; exists {
		view.Type = viewType.(string)
	}
	if isDefault, exists := data["is_default"]; exists {
		view.IsDefault = isDefault.(bool)
	}
	if isPublic, exists := data["is_public"]; exists {
		view.IsPublic = isPublic.(bool)
	}
	if position, exists := data["position"]; exists {
		view.Position = position.(int)
	}

	// Update JSON fields
	if layout, exists := data["layout"]; exists && layout != nil {
		if layoutStr, ok := layout.(string); ok {
			view.Layout = layoutStr
		} else {
			layoutBytes, _ := json.Marshal(layout)
			view.Layout = string(layoutBytes)
		}
	}

	if filters, exists := data["filters"]; exists && filters != nil {
		if filtersStr, ok := filters.(string); ok {
			view.Filters = filtersStr
		} else {
			filtersBytes, _ := json.Marshal(filters)
			view.Filters = string(filtersBytes)
		}
	}

	if sorting, exists := data["sorting"]; exists && sorting != nil {
		if sortingStr, ok := sorting.(string); ok {
			view.Sorting = sortingStr
		} else {
			sortingBytes, _ := json.Marshal(sorting)
			view.Sorting = string(sortingBytes)
		}
	}

	if grouping, exists := data["grouping"]; exists && grouping != nil {
		if groupingStr, ok := grouping.(string); ok {
			view.Grouping = groupingStr
		} else {
			groupingBytes, _ := json.Marshal(grouping)
			view.Grouping = string(groupingBytes)
		}
	}

	view.BaseModel.UpdatedBy = data["updated_by"].(*string)

	err = facades.Orm().Query().Save(view)
	if err != nil {
		return nil, err
	}

	// Log activity
	s.auditService.LogEventCompat(nil, "project_view.updated", "Project view updated", "", "", map[string]interface{}{
		"view_id":    view.ID,
		"name":       view.Name,
		"type":       view.Type,
		"project_id": view.ProjectID,
	}, "low")

	return view, nil
}

// DeleteView deletes a project view
func (s *ProjectViewService) DeleteView(id string, deletedBy *string) error {
	view, err := s.GetView(id)
	if err != nil {
		return err
	}

	// Cannot delete default view
	if view.IsDefault {
		return errors.New("cannot delete default view")
	}

	view.BaseModel.DeletedBy = deletedBy
	_, err = facades.Orm().Query().Delete(view)
	if err != nil {
		return err
	}

	// Log activity
	s.auditService.LogEventCompat(nil, "project_view.deleted", "Project view deleted", "", "", map[string]interface{}{
		"view_id":    view.ID,
		"name":       view.Name,
		"type":       view.Type,
		"project_id": view.ProjectID,
	}, "low")

	return nil
}

// ListViews retrieves all views for a project
func (s *ProjectViewService) ListViews(projectID string, filters map[string]interface{}) ([]models.ProjectView, error) {
	var views []models.ProjectView
	query := facades.Orm().Query().Where("project_id = ?", projectID)

	// Apply filters
	if isPublic, exists := filters["is_public"]; exists {
		query = query.Where("is_public = ?", isPublic)
	}
	if viewType, exists := filters["type"]; exists {
		query = query.Where("type = ?", viewType)
	}

	err := query.OrderBy("position", "ASC").OrderBy("created_at", "ASC").Find(&views)
	if err != nil {
		return nil, err
	}

	return views, nil
}

// SetDefaultView sets a view as the default for a project
func (s *ProjectViewService) SetDefaultView(viewID string, updatedBy *string) error {
	view, err := s.GetView(viewID)
	if err != nil {
		return err
	}

	// Remove default from other views in the same project
	_, err = facades.Orm().Query().
		Model(&models.ProjectView{}).
		Where("project_id = ? AND id != ?", view.ProjectID, viewID).
		Update("is_default", false)
	if err != nil {
		return err
	}

	// Set this view as default
	view.IsDefault = true
	view.BaseModel.UpdatedBy = updatedBy
	err = facades.Orm().Query().Save(view)
	if err != nil {
		return err
	}

	// Log activity
	s.auditService.LogEventCompat(nil, "project_view.default_set", "Project default view changed", "", "", map[string]interface{}{
		"view_id":    view.ID,
		"name":       view.Name,
		"project_id": view.ProjectID,
	}, "low")

	return nil
}

// DuplicateView creates a copy of an existing view
func (s *ProjectViewService) DuplicateView(viewID string, newName string, createdBy *string) (*models.ProjectView, error) {
	originalView, err := s.GetView(viewID)
	if err != nil {
		return nil, err
	}

	// Create duplicate
	duplicateView := &models.ProjectView{
		BaseModel: models.BaseModel{
			CreatedBy: createdBy,
		},
		Name:        newName,
		Description: originalView.Description + " (Copy)",
		Type:        originalView.Type,
		Layout:      originalView.Layout,
		Filters:     originalView.Filters,
		Sorting:     originalView.Sorting,
		Grouping:    originalView.Grouping,
		IsDefault:   false, // Duplicates are never default
		IsPublic:    originalView.IsPublic,
		Position:    originalView.Position + 1,
		ProjectID:   originalView.ProjectID,
	}

	err = facades.Orm().Query().Create(duplicateView)
	if err != nil {
		return nil, err
	}

	// Log activity
	s.auditService.LogEventCompat(nil, "project_view.duplicated", "Project view duplicated", "", "", map[string]interface{}{
		"original_view_id": originalView.ID,
		"new_view_id":      duplicateView.ID,
		"name":             duplicateView.Name,
		"project_id":       duplicateView.ProjectID,
	}, "low")

	return duplicateView, nil
}
