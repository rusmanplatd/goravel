package services

import (
	"encoding/json"
	"errors"

	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type ProjectCustomFieldService struct {
	auditService *AuditService
}

func NewProjectCustomFieldService() *ProjectCustomFieldService {
	return &ProjectCustomFieldService{
		auditService: NewAuditService(),
	}
}

// CreateField creates a new custom field for a project
func (s *ProjectCustomFieldService) CreateField(data map[string]interface{}) (*models.ProjectCustomField, error) {
	// Set default values
	if data["is_required"] == nil {
		data["is_required"] = false
	}
	if data["is_active"] == nil {
		data["is_active"] = true
	}
	if data["position"] == nil {
		// Get the highest position and add 1
		var maxPosition int
		facades.Orm().Query().Model(&models.ProjectCustomField{}).
			Where("project_id = ?", data["project_id"]).
			Select("COALESCE(MAX(position), 0)").Scan(&maxPosition)
		data["position"] = maxPosition + 1
	}

	// Create field
	field := &models.ProjectCustomField{
		BaseModel: models.BaseModel{
			CreatedBy: data["created_by"].(*string),
		},
		Name:        data["name"].(string),
		Description: data["description"].(string),
		Type:        data["type"].(string),
		IsRequired:  data["is_required"].(bool),
		IsActive:    data["is_active"].(bool),
		Position:    data["position"].(int),
		ProjectID:   data["project_id"].(string),
	}

	// Set options for select fields
	if options, exists := data["options"]; exists && options != nil {
		if optionsStr, ok := options.(string); ok {
			field.Options = optionsStr
		} else {
			optionsBytes, _ := json.Marshal(options)
			field.Options = string(optionsBytes)
		}
	}

	err := facades.Orm().Query().Create(field)
	if err != nil {
		return nil, err
	}

	// Log activity
	s.auditService.LogEventCompat(nil, "project_custom_field.created", "Custom field created", "", "", map[string]interface{}{
		"field_id":   field.ID,
		"name":       field.Name,
		"type":       field.Type,
		"project_id": field.ProjectID,
	}, "low")

	return field, nil
}

// GetField retrieves a custom field by ID
func (s *ProjectCustomFieldService) GetField(id string) (*models.ProjectCustomField, error) {
	field := &models.ProjectCustomField{}
	err := facades.Orm().Query().Where("id = ?", id).First(field)
	if err != nil {
		return nil, err
	}
	return field, nil
}

// UpdateField updates a custom field
func (s *ProjectCustomFieldService) UpdateField(id string, data map[string]interface{}) (*models.ProjectCustomField, error) {
	field, err := s.GetField(id)
	if err != nil {
		return nil, err
	}

	// Update fields
	if name, exists := data["name"]; exists {
		field.Name = name.(string)
	}
	if description, exists := data["description"]; exists {
		field.Description = description.(string)
	}
	if fieldType, exists := data["type"]; exists {
		field.Type = fieldType.(string)
	}
	if isRequired, exists := data["is_required"]; exists {
		field.IsRequired = isRequired.(bool)
	}
	if isActive, exists := data["is_active"]; exists {
		field.IsActive = isActive.(bool)
	}
	if position, exists := data["position"]; exists {
		field.Position = position.(int)
	}

	// Update options
	if options, exists := data["options"]; exists && options != nil {
		if optionsStr, ok := options.(string); ok {
			field.Options = optionsStr
		} else {
			optionsBytes, _ := json.Marshal(options)
			field.Options = string(optionsBytes)
		}
	}

	field.BaseModel.UpdatedBy = data["updated_by"].(*string)

	err = facades.Orm().Query().Save(field)
	if err != nil {
		return nil, err
	}

	// Log activity
	s.auditService.LogEventCompat(nil, "project_custom_field.updated", "Custom field updated", "", "", map[string]interface{}{
		"field_id":   field.ID,
		"name":       field.Name,
		"type":       field.Type,
		"project_id": field.ProjectID,
	}, "low")

	return field, nil
}

// DeleteField deletes a custom field
func (s *ProjectCustomFieldService) DeleteField(id string, deletedBy *string) error {
	field, err := s.GetField(id)
	if err != nil {
		return err
	}

	// Check if field is being used by tasks
	var count int64
	count, err = facades.Orm().Query().Model(&models.TaskFieldValue{}).Where("field_id = ?", id).Count()
	if err != nil {
		return err
	}

	if count > 0 {
		return errors.New("cannot delete field that is being used by tasks")
	}

	field.BaseModel.DeletedBy = deletedBy
	_, err = facades.Orm().Query().Delete(field)
	if err != nil {
		return err
	}

	// Log activity
	s.auditService.LogEventCompat(nil, "project_custom_field.deleted", "Custom field deleted", "", "", map[string]interface{}{
		"field_id":   field.ID,
		"name":       field.Name,
		"type":       field.Type,
		"project_id": field.ProjectID,
	}, "low")

	return nil
}

// ListFields retrieves all custom fields for a project
func (s *ProjectCustomFieldService) ListFields(projectID string, filters map[string]interface{}) ([]models.ProjectCustomField, error) {
	var fields []models.ProjectCustomField
	query := facades.Orm().Query().Where("project_id = ?", projectID)

	// Apply filters
	if isActive, exists := filters["is_active"]; exists {
		query = query.Where("is_active = ?", isActive)
	}
	if fieldType, exists := filters["type"]; exists {
		query = query.Where("type = ?", fieldType)
	}

	err := query.OrderBy("position", "ASC").OrderBy("created_at", "ASC").Find(&fields)
	if err != nil {
		return nil, err
	}

	return fields, nil
}

// ReorderFields updates the position of multiple fields
func (s *ProjectCustomFieldService) ReorderFields(fieldPositions map[string]int, updatedBy *string) error {
	for fieldID, position := range fieldPositions {
		_, err := facades.Orm().Query().
			Model(&models.ProjectCustomField{}).
			Where("id = ?", fieldID).
			Update("position", position)
		if err != nil {
			return err
		}
	}

	// Log activity
	s.auditService.LogEventCompat(nil, "project_custom_field.reordered", "Custom fields reordered", "", "", map[string]interface{}{
		"field_count": len(fieldPositions),
	}, "low")

	return nil
}

// SetFieldValue sets a custom field value for a task
func (s *ProjectCustomFieldService) SetFieldValue(taskID, fieldID string, value interface{}, createdBy *string) (*models.TaskFieldValue, error) {
	// Check if field value already exists
	var existingValue models.TaskFieldValue
	err := facades.Orm().Query().Where("task_id = ? AND field_id = ?", taskID, fieldID).First(&existingValue)

	if err != nil {
		// Create new value
		fieldValue := &models.TaskFieldValue{
			BaseModel: models.BaseModel{
				CreatedBy: createdBy,
			},
			TaskID:  taskID,
			FieldID: fieldID,
		}

		// Set value based on type
		if valueStr, ok := value.(string); ok {
			fieldValue.Value = valueStr
		} else {
			valueBytes, _ := json.Marshal(value)
			fieldValue.ValueJSON = string(valueBytes)
		}

		err = facades.Orm().Query().Create(fieldValue)
		if err != nil {
			return nil, err
		}

		return fieldValue, nil
	} else {
		// Update existing value
		if valueStr, ok := value.(string); ok {
			existingValue.Value = valueStr
			existingValue.ValueJSON = ""
		} else {
			valueBytes, _ := json.Marshal(value)
			existingValue.ValueJSON = string(valueBytes)
			existingValue.Value = ""
		}

		existingValue.BaseModel.UpdatedBy = createdBy

		err = facades.Orm().Query().Save(&existingValue)
		if err != nil {
			return nil, err
		}

		return &existingValue, nil
	}
}

// GetFieldValue gets a custom field value for a task
func (s *ProjectCustomFieldService) GetFieldValue(taskID, fieldID string) (*models.TaskFieldValue, error) {
	var fieldValue models.TaskFieldValue
	err := facades.Orm().Query().Where("task_id = ? AND field_id = ?", taskID, fieldID).First(&fieldValue)
	if err != nil {
		return nil, err
	}
	return &fieldValue, nil
}

// GetTaskFieldValues gets all custom field values for a task
func (s *ProjectCustomFieldService) GetTaskFieldValues(taskID string) ([]models.TaskFieldValue, error) {
	var fieldValues []models.TaskFieldValue
	err := facades.Orm().Query().
		Where("task_id = ?", taskID).
		With("Field").
		Find(&fieldValues)
	if err != nil {
		return nil, err
	}
	return fieldValues, nil
}
