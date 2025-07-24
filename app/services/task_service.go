package services

import (
	"errors"
	"time"

	"goravel/app/helpers"
	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type TaskService struct {
	auditService *AuditService
}

func NewTaskService() *TaskService {
	return &TaskService{
		auditService: NewAuditService(),
	}
}

// CreateTask creates a new task
func (s *TaskService) CreateTask(data map[string]interface{}) (*models.Task, error) {
	// Get next task number for the project
	projectID := data["project_id"].(string)
	var maxNumber int
	facades.Orm().Query().Model(&models.Task{}).Where("project_id = ?", projectID).Select("COALESCE(MAX(number), 0)").Scan(&maxNumber)
	data["number"] = maxNumber + 1

	// Set default values
	if data["is_active"] == nil {
		data["is_active"] = true
	}
	if data["is_archived"] == nil {
		data["is_archived"] = false
	}
	if data["progress"] == nil {
		data["progress"] = 0.0
	}
	if data["actual_hours"] == nil {
		data["actual_hours"] = 0.0
	}
	if data["position"] == nil {
		data["position"] = 0
	}

	// Create task
	task := &models.Task{
		BaseModel: models.BaseModel{
			CreatedBy: data["created_by"].(*string),
		},
		Title:       data["title"].(string),
		Description: data["description"].(string),
		Number:      data["number"].(int),
		Status:      data["status"].(string),
		Priority:    data["priority"].(string),
		Type:        data["type"].(string),
		Color:       data["color"].(string),
		Icon:        data["icon"].(string),
		IsActive:    data["is_active"].(bool),
		IsArchived:  data["is_archived"].(bool),
		ProjectID:   data["project_id"].(string),
		Progress:    data["progress"].(float64),
		ActualHours: data["actual_hours"].(float64),
		Position:    data["position"].(int),
	}

	// Set optional fields
	if assigneeID, exists := data["assignee_id"]; exists && assigneeID != nil {
		assigneeIDStr := assigneeID.(string)
		task.AssigneeID = &assigneeIDStr
	}
	if reviewerID, exists := data["reviewer_id"]; exists && reviewerID != nil {
		reviewerIDStr := reviewerID.(string)
		task.ReviewerID = &reviewerIDStr
	}
	if milestoneID, exists := data["milestone_id"]; exists && milestoneID != nil {
		milestoneIDStr := milestoneID.(string)
		task.MilestoneID = &milestoneIDStr
	}
	if parentTaskID, exists := data["parent_task_id"]; exists && parentTaskID != nil {
		parentTaskIDStr := parentTaskID.(string)
		task.ParentTaskID = &parentTaskIDStr
	}
	if startDate, exists := data["start_date"]; exists && startDate != nil {
		task.StartDate = startDate.(*time.Time)
	}
	if dueDate, exists := data["due_date"]; exists && dueDate != nil {
		task.DueDate = dueDate.(*time.Time)
	}
	if estimatedHours, exists := data["estimated_hours"]; exists {
		task.EstimatedHours = estimatedHours.(float64)
	}
	if settings, exists := data["settings"]; exists && settings != nil {
		task.Settings = settings.(string)
	}

	err := facades.Orm().Query().Create(task)
	if err != nil {
		return nil, err
	}

	// Log activity
	s.auditService.LogEvent(nil, "task.created", "Task created", "", "", map[string]interface{}{
		"task_id":    task.ID,
		"title":      task.Title,
		"project_id": task.ProjectID,
		"number":     task.Number,
	}, "low")

	return task, nil
}

// GetTask retrieves a task by ID
func (s *TaskService) GetTask(id string) (*models.Task, error) {
	task := &models.Task{}
	err := facades.Orm().Query().Where("id = ?", id).First(task)
	if err != nil {
		return nil, err
	}
	return task, nil
}

// UpdateTask updates a task
func (s *TaskService) UpdateTask(id string, data map[string]interface{}) (*models.Task, error) {
	task := &models.Task{}
	err := facades.Orm().Query().Where("id = ?", id).First(task)
	if err != nil {
		return nil, err
	}

	// Update task fields
	if title, exists := data["title"]; exists {
		task.Title = title.(string)
	}
	if description, exists := data["description"]; exists {
		task.Description = description.(string)
	}
	if status, exists := data["status"]; exists {
		task.Status = status.(string)
	}
	if priority, exists := data["priority"]; exists {
		task.Priority = priority.(string)
	}
	if taskType, exists := data["type"]; exists {
		task.Type = taskType.(string)
	}
	if color, exists := data["color"]; exists {
		task.Color = color.(string)
	}
	if icon, exists := data["icon"]; exists {
		task.Icon = icon.(string)
	}
	if isActive, exists := data["is_active"]; exists {
		task.IsActive = isActive.(bool)
	}
	if isArchived, exists := data["is_archived"]; exists {
		task.IsArchived = isArchived.(bool)
	}
	if progress, exists := data["progress"]; exists {
		task.Progress = progress.(float64)
	}
	if actualHours, exists := data["actual_hours"]; exists {
		task.ActualHours = actualHours.(float64)
	}
	if position, exists := data["position"]; exists {
		task.Position = position.(int)
	}
	if estimatedHours, exists := data["estimated_hours"]; exists {
		task.EstimatedHours = estimatedHours.(float64)
	}
	if startDate, exists := data["start_date"]; exists {
		if startDate != nil {
			task.StartDate = startDate.(*time.Time)
		} else {
			task.StartDate = nil
		}
	}
	if dueDate, exists := data["due_date"]; exists {
		if dueDate != nil {
			task.DueDate = dueDate.(*time.Time)
		} else {
			task.DueDate = nil
		}
	}
	if assigneeID, exists := data["assignee_id"]; exists {
		if assigneeID != nil {
			assigneeIDStr := assigneeID.(string)
			task.AssigneeID = &assigneeIDStr
		} else {
			task.AssigneeID = nil
		}
	}
	if reviewerID, exists := data["reviewer_id"]; exists {
		if reviewerID != nil {
			reviewerIDStr := reviewerID.(string)
			task.ReviewerID = &reviewerIDStr
		} else {
			task.ReviewerID = nil
		}
	}
	if milestoneID, exists := data["milestone_id"]; exists {
		if milestoneID != nil {
			milestoneIDStr := milestoneID.(string)
			task.MilestoneID = &milestoneIDStr
		} else {
			task.MilestoneID = nil
		}
	}
	if parentTaskID, exists := data["parent_task_id"]; exists {
		if parentTaskID != nil {
			parentTaskIDStr := parentTaskID.(string)
			task.ParentTaskID = &parentTaskIDStr
		} else {
			task.ParentTaskID = nil
		}
	}
	if settings, exists := data["settings"]; exists {
		task.Settings = settings.(string)
	}

	// Save task
	err = facades.Orm().Query().Save(task)
	if err != nil {
		return nil, err
	}

	// Log activity
	s.auditService.LogEvent(nil, "task.updated", "Task updated", "", "", map[string]interface{}{
		"task_id":    task.ID,
		"title":      task.Title,
		"project_id": task.ProjectID,
	}, "low")

	return task, nil
}

// DeleteTask deletes a task
func (s *TaskService) DeleteTask(id string) error {
	task := &models.Task{}
	err := facades.Orm().Query().Where("id = ?", id).First(task)
	if err != nil {
		return err
	}

	// Check if task has subtasks
	var subtaskCount int64
	subtaskCount, _ = facades.Orm().Query().Model(&models.Task{}).Where("parent_task_id = ?", id).Count()
	if subtaskCount > 0 {
		return errors.New("cannot delete task with subtasks")
	}

	// Check if task has dependencies
	var dependencyCount int64
	dependencyCount, _ = facades.Orm().Query().Model(&models.TaskDependency{}).Where("task_id = ? OR dependent_task_id = ?", id, id).Count()
	if dependencyCount > 0 {
		return errors.New("cannot delete task with dependencies")
	}

	// Delete task
	_, err = facades.Orm().Query().Where("id = ?", id).Delete(task)
	if err != nil {
		return err
	}

	// Log activity
	s.auditService.LogEvent(nil, "task.deleted", "Task deleted", "", "", map[string]interface{}{
		"task_id":    task.ID,
		"title":      task.Title,
		"project_id": task.ProjectID,
	}, "low")

	return nil
}

// ListTasks retrieves tasks with filtering and pagination
func (s *TaskService) ListTasks(filters map[string]interface{}, cursor string, limit int) ([]models.Task, map[string]interface{}, error) {
	query := facades.Orm().Query().Model(&models.Task{})

	// Apply filters
	if projectID, exists := filters["project_id"]; exists {
		query = query.Where("project_id = ?", projectID)
	}
	if search, exists := filters["search"]; exists && search != "" {
		searchStr := search.(string)
		query = query.Where("title LIKE ? OR description LIKE ?", "%"+searchStr+"%", "%"+searchStr+"%")
	}
	if status, exists := filters["status"]; exists && status != "" {
		query = query.Where("status = ?", status)
	}
	if priority, exists := filters["priority"]; exists && priority != "" {
		query = query.Where("priority = ?", priority)
	}
	if taskType, exists := filters["type"]; exists && taskType != "" {
		query = query.Where("type = ?", taskType)
	}
	if assigneeID, exists := filters["assignee_id"]; exists && assigneeID != "" {
		query = query.Where("assignee_id = ?", assigneeID)
	}
	if milestoneID, exists := filters["milestone_id"]; exists && milestoneID != "" {
		query = query.Where("milestone_id = ?", milestoneID)
	}
	if parentTaskID, exists := filters["parent_task_id"]; exists {
		if parentTaskID == nil {
			query = query.Where("parent_task_id IS NULL")
		} else {
			query = query.Where("parent_task_id = ?", parentTaskID)
		}
	}
	if isActive, exists := filters["is_active"]; exists {
		query = query.Where("is_active = ?", isActive)
	}
	if isArchived, exists := filters["is_archived"]; exists {
		query = query.Where("is_archived = ?", isArchived)
	}

	// Apply cursor-based pagination
	query, err := helpers.ApplyCursorPagination(query, cursor, limit, false)
	if err != nil {
		return nil, nil, err
	}

	var tasks []models.Task
	err = query.Find(&tasks)
	if err != nil {
		return nil, nil, err
	}

	// Check if there are more results
	hasMore := false
	if len(tasks) > limit {
		hasMore = true
		tasks = tasks[:limit] // Remove the extra item
	}

	// Build pagination info
	paginationInfo := helpers.BuildPaginationInfo(tasks, limit, cursor, hasMore)

	return tasks, paginationInfo, nil
}

// CreateTaskLabel creates a new task label
func (s *TaskService) CreateTaskLabel(data map[string]interface{}) (*models.TaskLabel, error) {
	// Set default values
	if data["is_active"] == nil {
		data["is_active"] = true
	}

	// Create label
	label := &models.TaskLabel{
		Name:        data["name"].(string),
		Description: data["description"].(string),
		Color:       data["color"].(string),
		Icon:        data["icon"].(string),
		IsActive:    data["is_active"].(bool),
		ProjectID:   data["project_id"].(string),
		BaseModel: models.BaseModel{
			CreatedBy: data["created_by"].(*string),
		},
	}

	err := facades.Orm().Query().Create(label)
	if err != nil {
		return nil, err
	}

	// Log activity
	s.auditService.LogEvent(nil, "task_label.created", "Task label created", "", "", map[string]interface{}{
		"label_id":   label.ID,
		"name":       label.Name,
		"project_id": label.ProjectID,
	}, "low")

	return label, nil
}

// GetTaskLabel retrieves a task label by ID
func (s *TaskService) GetTaskLabel(id string) (*models.TaskLabel, error) {
	label := &models.TaskLabel{}
	err := facades.Orm().Query().Where("id = ?", id).First(label)
	if err != nil {
		return nil, err
	}
	return label, nil
}

// UpdateTaskLabel updates a task label
func (s *TaskService) UpdateTaskLabel(id string, data map[string]interface{}) (*models.TaskLabel, error) {
	label := &models.TaskLabel{}
	err := facades.Orm().Query().Where("id = ?", id).First(label)
	if err != nil {
		return nil, err
	}

	// Update label fields
	if name, exists := data["name"]; exists {
		label.Name = name.(string)
	}
	if description, exists := data["description"]; exists {
		label.Description = description.(string)
	}
	if color, exists := data["color"]; exists {
		label.Color = color.(string)
	}
	if icon, exists := data["icon"]; exists {
		label.Icon = icon.(string)
	}
	if isActive, exists := data["is_active"]; exists {
		label.IsActive = isActive.(bool)
	}

	// Save label
	err = facades.Orm().Query().Save(label)
	if err != nil {
		return nil, err
	}

	// Log activity
	s.auditService.LogEvent(nil, "task_label.updated", "Task label updated", "", "", map[string]interface{}{
		"label_id":   label.ID,
		"name":       label.Name,
		"project_id": label.ProjectID,
	}, "low")

	return label, nil
}

// DeleteTaskLabel deletes a task label
func (s *TaskService) DeleteTaskLabel(id string) error {
	label := &models.TaskLabel{}
	err := facades.Orm().Query().Where("id = ?", id).First(label)
	if err != nil {
		return err
	}

	// Check if label is used by any tasks
	var taskCount int64
	taskCount, _ = facades.Orm().Query().Model(&models.TaskLabelPivot{}).Where("label_id = ?", id).Count()
	if taskCount > 0 {
		return errors.New("cannot delete label that is used by tasks")
	}

	// Delete label
	_, err = facades.Orm().Query().Where("id = ?", id).Delete(label)
	if err != nil {
		return err
	}

	// Log activity
	s.auditService.LogEvent(nil, "task_label.deleted", "Task label deleted", "", "", map[string]interface{}{
		"label_id":   label.ID,
		"name":       label.Name,
		"project_id": label.ProjectID,
	}, "low")

	return nil
}

// ListTaskLabels retrieves task labels with filtering
func (s *TaskService) ListTaskLabels(filters map[string]interface{}) ([]models.TaskLabel, error) {
	query := facades.Orm().Query().Model(&models.TaskLabel{})

	// Apply filters
	if projectID, exists := filters["project_id"]; exists {
		query = query.Where("project_id = ?", projectID)
	}
	if isActive, exists := filters["is_active"]; exists {
		query = query.Where("is_active = ?", isActive)
	}

	var labels []models.TaskLabel
	err := query.Find(&labels)
	if err != nil {
		return nil, err
	}

	return labels, nil
}

// AddLabelToTask adds a label to a task
func (s *TaskService) AddLabelToTask(taskID, labelID, userID string) error {
	// Check if label-task relationship already exists
	var existingPivot models.TaskLabelPivot
	err := facades.Orm().Query().Where("task_id = ? AND label_id = ?", taskID, labelID).First(&existingPivot)
	if err == nil {
		return errors.New("label is already added to this task")
	}

	// Create label-task relationship
	pivot := &models.TaskLabelPivot{
		TaskID:  taskID,
		LabelID: labelID,
		AddedAt: time.Now(),
		AddedBy: userID,
	}

	err = facades.Orm().Query().Create(pivot)
	if err != nil {
		return err
	}

	// Log activity
	s.auditService.LogEvent(nil, "task.label_added", "Label added to task", "", "", map[string]interface{}{
		"task_id":  taskID,
		"label_id": labelID,
	}, "low")

	return nil
}

// RemoveLabelFromTask removes a label from a task
func (s *TaskService) RemoveLabelFromTask(taskID, labelID string) error {
	// Delete label-task relationship
	_, err := facades.Orm().Query().Where("task_id = ? AND label_id = ?", taskID, labelID).Delete(&models.TaskLabelPivot{})
	if err != nil {
		return err
	}

	// Log activity
	s.auditService.LogEvent(nil, "task.label_removed", "Label removed from task", "", "", map[string]interface{}{
		"task_id":  taskID,
		"label_id": labelID,
	}, "low")

	return nil
}

// CreateMilestone creates a new milestone
func (s *TaskService) CreateMilestone(data map[string]interface{}) (*models.Milestone, error) {
	// Set default values
	if data["status"] == nil {
		data["status"] = "open"
	}
	if data["progress"] == nil {
		data["progress"] = 0.0
	}

	// Create milestone
	milestone := &models.Milestone{
		BaseModel: models.BaseModel{
			CreatedBy: data["created_by"].(*string),
		},
		Title:       data["title"].(string),
		Description: data["description"].(string),
		Status:      data["status"].(string),
		Color:       data["color"].(string),
		Icon:        data["icon"].(string),
		ProjectID:   data["project_id"].(string),
		Progress:    data["progress"].(float64),
	}

	// Set optional fields
	if dueDate, exists := data["due_date"]; exists && dueDate != nil {
		milestone.DueDate = dueDate.(*time.Time)
	}

	err := facades.Orm().Query().Create(milestone)
	if err != nil {
		return nil, err
	}

	// Log activity
	s.auditService.LogEvent(nil, "milestone.created", "Milestone created", "", "", map[string]interface{}{
		"milestone_id": milestone.ID,
		"title":        milestone.Title,
		"project_id":   milestone.ProjectID,
	}, "low")

	return milestone, nil
}

// GetMilestone retrieves a milestone by ID
func (s *TaskService) GetMilestone(id string) (*models.Milestone, error) {
	milestone := &models.Milestone{}
	err := facades.Orm().Query().Where("id = ?", id).First(milestone)
	if err != nil {
		return nil, err
	}
	return milestone, nil
}

// UpdateMilestone updates a milestone
func (s *TaskService) UpdateMilestone(id string, data map[string]interface{}) (*models.Milestone, error) {
	milestone := &models.Milestone{}
	err := facades.Orm().Query().Where("id = ?", id).First(milestone)
	if err != nil {
		return nil, err
	}

	// Update milestone fields
	if title, exists := data["title"]; exists {
		milestone.Title = title.(string)
	}
	if description, exists := data["description"]; exists {
		milestone.Description = description.(string)
	}
	if status, exists := data["status"]; exists {
		milestone.Status = status.(string)
	}
	if color, exists := data["color"]; exists {
		milestone.Color = color.(string)
	}
	if icon, exists := data["icon"]; exists {
		milestone.Icon = icon.(string)
	}
	if progress, exists := data["progress"]; exists {
		milestone.Progress = progress.(float64)
	}
	if dueDate, exists := data["due_date"]; exists {
		if dueDate != nil {
			milestone.DueDate = dueDate.(*time.Time)
		} else {
			milestone.DueDate = nil
		}
	}
	if completedAt, exists := data["completed_at"]; exists {
		if completedAt != nil {
			milestone.CompletedAt = completedAt.(*time.Time)
		} else {
			milestone.CompletedAt = nil
		}
	}

	// Save milestone
	err = facades.Orm().Query().Save(milestone)
	if err != nil {
		return nil, err
	}

	// Log activity
	s.auditService.LogEvent(nil, "milestone.updated", "Milestone updated", "", "", map[string]interface{}{
		"milestone_id": milestone.ID,
		"title":        milestone.Title,
		"project_id":   milestone.ProjectID,
	}, "low")

	return milestone, nil
}

// DeleteMilestone deletes a milestone
func (s *TaskService) DeleteMilestone(id string) error {
	milestone := &models.Milestone{}
	err := facades.Orm().Query().Where("id = ?", id).First(milestone)
	if err != nil {
		return err
	}

	// Check if milestone has tasks
	var taskCount int64
	taskCount, _ = facades.Orm().Query().Model(&models.Task{}).Where("milestone_id = ?", id).Count()
	if taskCount > 0 {
		return errors.New("cannot delete milestone with tasks")
	}

	// Delete milestone
	_, err = facades.Orm().Query().Where("id = ?", id).Delete(milestone)
	if err != nil {
		return err
	}

	// Log activity
	s.auditService.LogEvent(nil, "milestone.deleted", "Milestone deleted", "", "", map[string]interface{}{
		"milestone_id": milestone.ID,
		"title":        milestone.Title,
		"project_id":   milestone.ProjectID,
	}, "low")

	return nil
}

// ListMilestones retrieves milestones with filtering
func (s *TaskService) ListMilestones(filters map[string]interface{}) ([]models.Milestone, error) {
	query := facades.Orm().Query().Model(&models.Milestone{})

	// Apply filters
	if projectID, exists := filters["project_id"]; exists {
		query = query.Where("project_id = ?", projectID)
	}
	if status, exists := filters["status"]; exists && status != "" {
		query = query.Where("status = ?", status)
	}

	var milestones []models.Milestone
	err := query.Find(&milestones)
	if err != nil {
		return nil, err
	}

	return milestones, nil
}

// CreateTaskBoard creates a new task board
func (s *TaskService) CreateTaskBoard(data map[string]interface{}) (*models.TaskBoard, error) {
	// Set default values
	if data["type"] == nil {
		data["type"] = "kanban"
	}
	if data["is_active"] == nil {
		data["is_active"] = true
	}
	if data["is_default"] == nil {
		data["is_default"] = false
	}

	// If this is the first board for the project, make it default
	if data["is_default"].(bool) {
		var boardCount int64
		boardCount, _ = facades.Orm().Query().Model(&models.TaskBoard{}).Where("project_id = ?", data["project_id"]).Count()
		if boardCount == 0 {
			data["is_default"] = true
		}
	}

	// Create board
	board := &models.TaskBoard{
		Name:        data["name"].(string),
		Description: data["description"].(string),
		Type:        data["type"].(string),
		Color:       data["color"].(string),
		Icon:        data["icon"].(string),
		IsActive:    data["is_active"].(bool),
		IsDefault:   data["is_default"].(bool),
		ProjectID:   data["project_id"].(string),
		BaseModel: models.BaseModel{
			CreatedBy: data["created_by"].(*string),
		},
	}

	// Set optional fields
	if settings, exists := data["settings"]; exists && settings != nil {
		board.Settings = settings.(string)
	}

	err := facades.Orm().Query().Create(board)
	if err != nil {
		return nil, err
	}

	// Log activity
	s.auditService.LogEvent(nil, "task_board.created", "Task board created", "", "", map[string]interface{}{
		"board_id":   board.ID,
		"name":       board.Name,
		"project_id": board.ProjectID,
	}, "low")

	return board, nil
}

// GetTaskBoard retrieves a task board by ID
func (s *TaskService) GetTaskBoard(id string) (*models.TaskBoard, error) {
	board := &models.TaskBoard{}
	err := facades.Orm().Query().Where("id = ?", id).First(board)
	if err != nil {
		return nil, err
	}
	return board, nil
}

// UpdateTaskBoard updates a task board
func (s *TaskService) UpdateTaskBoard(id string, data map[string]interface{}) (*models.TaskBoard, error) {
	board := &models.TaskBoard{}
	err := facades.Orm().Query().Where("id = ?", id).First(board)
	if err != nil {
		return nil, err
	}

	// Update board fields
	if name, exists := data["name"]; exists {
		board.Name = name.(string)
	}
	if description, exists := data["description"]; exists {
		board.Description = description.(string)
	}
	if boardType, exists := data["type"]; exists {
		board.Type = boardType.(string)
	}
	if color, exists := data["color"]; exists {
		board.Color = color.(string)
	}
	if icon, exists := data["icon"]; exists {
		board.Icon = icon.(string)
	}
	if isActive, exists := data["is_active"]; exists {
		board.IsActive = isActive.(bool)
	}
	if isDefault, exists := data["is_default"]; exists {
		board.IsDefault = isDefault.(bool)
	}
	if settings, exists := data["settings"]; exists {
		board.Settings = settings.(string)
	}

	// Save board
	err = facades.Orm().Query().Save(board)
	if err != nil {
		return nil, err
	}

	// Log activity
	s.auditService.LogEvent(nil, "task_board.updated", "Task board updated", "", "", map[string]interface{}{
		"board_id":   board.ID,
		"name":       board.Name,
		"project_id": board.ProjectID,
	}, "low")

	return board, nil
}

// DeleteTaskBoard deletes a task board
func (s *TaskService) DeleteTaskBoard(id string) error {
	board := &models.TaskBoard{}
	err := facades.Orm().Query().Where("id = ?", id).First(board)
	if err != nil {
		return err
	}

	// Check if board has columns
	var columnCount int64
	columnCount, _ = facades.Orm().Query().Model(&models.TaskBoardColumn{}).Where("board_id = ?", id).Count()
	if columnCount > 0 {
		return errors.New("cannot delete board with columns")
	}

	// Delete board
	_, err = facades.Orm().Query().Where("id = ?", id).Delete(board)
	if err != nil {
		return err
	}

	// Log activity
	s.auditService.LogEvent(nil, "task_board.deleted", "Task board deleted", "", "", map[string]interface{}{
		"board_id":   board.ID,
		"name":       board.Name,
		"project_id": board.ProjectID,
	}, "low")

	return nil
}

// ListTaskBoards retrieves task boards with filtering
func (s *TaskService) ListTaskBoards(filters map[string]interface{}) ([]models.TaskBoard, error) {
	query := facades.Orm().Query().Model(&models.TaskBoard{})

	// Apply filters
	if projectID, exists := filters["project_id"]; exists {
		query = query.Where("project_id = ?", projectID)
	}
	if boardType, exists := filters["type"]; exists && boardType != "" {
		query = query.Where("type = ?", boardType)
	}
	if isActive, exists := filters["is_active"]; exists {
		query = query.Where("is_active = ?", isActive)
	}
	if isDefault, exists := filters["is_default"]; exists {
		query = query.Where("is_default = ?", isDefault)
	}

	var boards []models.TaskBoard
	err := query.Find(&boards)
	if err != nil {
		return nil, err
	}

	return boards, nil
}
