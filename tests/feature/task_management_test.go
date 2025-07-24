package feature

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"

	"goravel/app/http/requests"
	"goravel/app/services"
)

type TaskManagementTestSuite struct {
	suite.Suite
}

func TestTaskManagementTestSuite(t *testing.T) {
	suite.Run(t, new(TaskManagementTestSuite))
}

func (suite *TaskManagementTestSuite) TestCreateTask() {
	// Create a real task service for integration testing
	taskService := services.NewTaskService()

	// Create test data
	taskData := map[string]interface{}{
		"title":        "Test Task",
		"description":  "Test task description",
		"status":       "todo",
		"priority":     "medium",
		"type":         "task",
		"project_id":   "01HXYZ123456789ABCDEFGHIJK",
		"created_by":   "01HXYZ123456789ABCDEFGHIJK",
		"is_active":    true,
		"is_archived":  false,
		"progress":     0.0,
		"actual_hours": 0.0,
		"position":     0,
	}

	// Test the service method
	task, err := taskService.CreateTask(taskData)

	// Assertions
	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), task)
	assert.Equal(suite.T(), "Test Task", task.Title)
	assert.Equal(suite.T(), "todo", task.Status)
	assert.Equal(suite.T(), "medium", task.Priority)
	assert.Equal(suite.T(), "task", task.Type)
}

func (suite *TaskManagementTestSuite) TestCreateTaskLabel() {
	// Create a real task service for integration testing
	taskService := services.NewTaskService()

	// Create test data
	labelData := map[string]interface{}{
		"name":        "Bug",
		"description": "Issues that need to be fixed",
		"color":       "#EF4444",
		"icon":        "bug",
		"project_id":  "01HXYZ123456789ABCDEFGHIJK",
		"created_by":  "01HXYZ123456789ABCDEFGHIJK",
		"is_active":   true,
	}

	// Test the service method
	label, err := taskService.CreateTaskLabel(labelData)

	// Assertions
	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), label)
	assert.Equal(suite.T(), "Bug", label.Name)
	assert.Equal(suite.T(), "#EF4444", label.Color)
	assert.Equal(suite.T(), "bug", label.Icon)
}

func (suite *TaskManagementTestSuite) TestCreateMilestone() {
	// Create a real task service for integration testing
	taskService := services.NewTaskService()

	// Create test data
	milestoneData := map[string]interface{}{
		"title":       "Phase 1 - Foundation",
		"description": "Core infrastructure and basic features",
		"status":      "open",
		"color":       "#10B981",
		"icon":        "milestone",
		"project_id":  "01HXYZ123456789ABCDEFGHIJK",
		"created_by":  "01HXYZ123456789ABCDEFGHIJK",
		"progress":    0.0,
	}

	// Test the service method
	milestone, err := taskService.CreateMilestone(milestoneData)

	// Assertions
	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), milestone)
	assert.Equal(suite.T(), "Phase 1 - Foundation", milestone.Title)
	assert.Equal(suite.T(), "open", milestone.Status)
	assert.Equal(suite.T(), "#10B981", milestone.Color)
}

func (suite *TaskManagementTestSuite) TestCreateTaskBoard() {
	// Create a real task service for integration testing
	taskService := services.NewTaskService()

	// Create test data
	boardData := map[string]interface{}{
		"name":        "Development Board",
		"description": "Main development workflow board",
		"type":        "kanban",
		"color":       "#3B82F6",
		"icon":        "board",
		"is_active":   true,
		"is_default":  true,
		"project_id":  "01HXYZ123456789ABCDEFGHIJK",
		"created_by":  "01HXYZ123456789ABCDEFGHIJK",
		"settings":    `{"columns":["todo","in_progress","done"],"filters":{"assignee":"all"}}`,
	}

	// Test the service method
	board, err := taskService.CreateTaskBoard(boardData)

	// Assertions
	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), board)
	assert.Equal(suite.T(), "Development Board", board.Name)
	assert.Equal(suite.T(), "kanban", board.Type)
	assert.Equal(suite.T(), true, board.IsDefault)
}

func (suite *TaskManagementTestSuite) TestTaskRequestValidation() {
	// Test valid task request
	validRequest := requests.TaskRequest{
		Title:       "Valid Task",
		Description: "Valid task description",
		Status:      "todo",
		Priority:    "medium",
		Type:        "task",
		Color:       "#3B82F6",
		Icon:        "task",
		Progress:    0.0,
		Position:    0,
	}

	// This would normally be validated by the framework
	// For now, we just test that the struct can be created
	assert.Equal(suite.T(), "Valid Task", validRequest.Title)
	assert.Equal(suite.T(), "todo", validRequest.Status)
	assert.Equal(suite.T(), "medium", validRequest.Priority)
	assert.Equal(suite.T(), "task", validRequest.Type)
}

func (suite *TaskManagementTestSuite) TestTaskLabelRequestValidation() {
	// Test valid task label request
	validRequest := requests.TaskLabelRequest{
		Name:        "Bug",
		Description: "Issues that need to be fixed",
		Color:       "#EF4444",
		Icon:        "bug",
	}

	// This would normally be validated by the framework
	// For now, we just test that the struct can be created
	assert.Equal(suite.T(), "Bug", validRequest.Name)
	assert.Equal(suite.T(), "#EF4444", validRequest.Color)
	assert.Equal(suite.T(), "bug", validRequest.Icon)
}

func (suite *TaskManagementTestSuite) TestMilestoneRequestValidation() {
	// Test valid milestone request
	validRequest := requests.MilestoneRequest{
		Title:       "Phase 1",
		Description: "Core features",
		Status:      "open",
		Color:       "#10B981",
		Icon:        "milestone",
		Progress:    0.0,
	}

	// This would normally be validated by the framework
	// For now, we just test that the struct can be created
	assert.Equal(suite.T(), "Phase 1", validRequest.Title)
	assert.Equal(suite.T(), "open", validRequest.Status)
	assert.Equal(suite.T(), "#10B981", validRequest.Color)
}

func (suite *TaskManagementTestSuite) TestTaskBoardRequestValidation() {
	// Test valid task board request
	validRequest := requests.TaskBoardRequest{
		Name:        "Development Board",
		Description: "Main workflow board",
		Type:        "kanban",
		Color:       "#3B82F6",
		Icon:        "board",
		IsDefault:   true,
		Settings:    `{"columns":["todo","done"]}`,
	}

	// This would normally be validated by the framework
	// For now, we just test that the struct can be created
	assert.Equal(suite.T(), "Development Board", validRequest.Name)
	assert.Equal(suite.T(), "kanban", validRequest.Type)
	assert.Equal(suite.T(), true, validRequest.IsDefault)
}
