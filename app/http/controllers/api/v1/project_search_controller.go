package v1

import (
	"fmt"
	"strings"
	"time"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/http/responses"
	"goravel/app/models"
)

type ProjectSearchController struct{}

func NewProjectSearchController() *ProjectSearchController {
	return &ProjectSearchController{}
}

// SearchProjects performs advanced search across projects
// @Summary Advanced project search
// @Description Search projects with advanced filtering and ranking (GitHub Projects v2 style)
// @Tags project-search
// @Accept json
// @Produce json
// @Param q query string false "Search query (searches name, description, readme)"
// @Param org_id query string false "Filter by organization ID"
// @Param owner_id query string false "Filter by owner ID"
// @Param state query string false "Filter by state" Enums(open,closed,all) default(all)
// @Param visibility query string false "Filter by visibility" Enums(private,public,all) default(all)
// @Param status query string false "Filter by status" Enums(planning,active,on_hold,completed,cancelled,all) default(all)
// @Param archived query string false "Include archived projects" Enums(true,false,only) default(false)
// @Param template query string false "Filter by template projects" Enums(true,false,only) default(false)
// @Param has_readme query bool false "Filter projects that have README content"
// @Param created_after query string false "Filter projects created after date (ISO 8601)"
// @Param created_before query string false "Filter projects created before date (ISO 8601)"
// @Param updated_after query string false "Filter projects updated after date (ISO 8601)"
// @Param sort query string false "Sort order" Enums(relevance,name,created_at,updated_at,activity) default(relevance)
// @Param order query string false "Sort direction" Enums(asc,desc) default(desc)
// @Param per_page query int false "Results per page" minimum(1) maximum(100) default(30)
// @Param page query int false "Page number" minimum(1) default(1)
// @Success 200 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Router /projects/search [get]
func (psc *ProjectSearchController) SearchProjects(ctx http.Context) http.Response {
	userID := ctx.Value("user_id").(string)

	// Parse search parameters
	query := strings.TrimSpace(ctx.Request().Query("q", ""))
	orgID := ctx.Request().Query("org_id", "")
	ownerID := ctx.Request().Query("owner_id", "")
	state := ctx.Request().Query("state", "all")
	visibility := ctx.Request().Query("visibility", "all")
	status := ctx.Request().Query("status", "all")
	archived := ctx.Request().Query("archived", "false")
	template := ctx.Request().Query("template", "false")
	hasReadme := ctx.Request().QueryBool("has_readme", false)
	sortBy := ctx.Request().Query("sort", "relevance")
	order := ctx.Request().Query("order", "desc")

	// Parse date filters
	var createdAfter, createdBefore, updatedAfter *time.Time
	if dateStr := ctx.Request().Query("created_after", ""); dateStr != "" {
		if parsed, err := time.Parse(time.RFC3339, dateStr); err == nil {
			createdAfter = &parsed
		}
	}
	if dateStr := ctx.Request().Query("created_before", ""); dateStr != "" {
		if parsed, err := time.Parse(time.RFC3339, dateStr); err == nil {
			createdBefore = &parsed
		}
	}
	if dateStr := ctx.Request().Query("updated_after", ""); dateStr != "" {
		if parsed, err := time.Parse(time.RFC3339, dateStr); err == nil {
			updatedAfter = &parsed
		}
	}

	// Build base query with access control
	baseQuery := `
		SELECT DISTINCT p.*, 
			   o.name as organization_name,
			   u.name as owner_name,
			   u.avatar as owner_avatar,
			   (CASE 
				   WHEN ? = p.owner_id THEN 1
				   WHEN uo.user_id IS NOT NULL THEN 1
				   WHEN p.visibility = 'public' THEN 1
				   ELSE 0
			   END) as can_access,
			   (CASE 
				   WHEN p.name ILIKE ? THEN 100
				   WHEN p.description ILIKE ? THEN 80
				   WHEN p.readme ILIKE ? THEN 60
				   ELSE 0
			   END) as relevance_score
		FROM projects p
		LEFT JOIN organizations o ON p.organization_id = o.id
		LEFT JOIN users u ON p.owner_id = u.id
		LEFT JOIN user_organizations uo ON (p.organization_id = uo.organization_id AND uo.user_id = ? AND uo.is_active = true)
		WHERE 1=1
	`

	args := []interface{}{userID, "%" + query + "%", "%" + query + "%", "%" + query + "%", userID}

	// Apply access control filter
	baseQuery += ` AND (? = p.owner_id OR uo.user_id IS NOT NULL OR p.visibility = 'public')`
	args = append(args, userID)

	// Apply search filters
	if query != "" {
		baseQuery += ` AND (p.name ILIKE ? OR p.description ILIKE ? OR p.readme ILIKE ?)`
		searchPattern := "%" + query + "%"
		args = append(args, searchPattern, searchPattern, searchPattern)
	}

	if orgID != "" {
		baseQuery += ` AND p.organization_id = ?`
		args = append(args, orgID)
	}

	if ownerID != "" {
		baseQuery += ` AND p.owner_id = ?`
		args = append(args, ownerID)
	}

	if state != "all" {
		baseQuery += ` AND p.state = ?`
		args = append(args, state)
	}

	if visibility != "all" {
		baseQuery += ` AND p.visibility = ?`
		args = append(args, visibility)
	}

	if status != "all" {
		baseQuery += ` AND p.status = ?`
		args = append(args, status)
	}

	// Handle archived filter
	switch archived {
	case "true":
		// Include archived projects
	case "only":
		baseQuery += ` AND p.is_archived = true`
	default: // "false"
		baseQuery += ` AND p.is_archived = false`
	}

	// Handle template filter
	switch template {
	case "true":
		// Include template projects
	case "only":
		baseQuery += ` AND p.is_template = true`
	default: // "false"
		baseQuery += ` AND p.is_template = false`
	}

	if hasReadme {
		baseQuery += ` AND p.readme IS NOT NULL AND p.readme != ''`
	}

	// Apply date filters
	if createdAfter != nil {
		baseQuery += ` AND p.created_at >= ?`
		args = append(args, *createdAfter)
	}
	if createdBefore != nil {
		baseQuery += ` AND p.created_at <= ?`
		args = append(args, *createdBefore)
	}
	if updatedAfter != nil {
		baseQuery += ` AND p.updated_at >= ?`
		args = append(args, *updatedAfter)
	}

	// Apply sorting
	switch sortBy {
	case "relevance":
		if query != "" {
			baseQuery += ` ORDER BY relevance_score DESC, p.updated_at DESC`
		} else {
			baseQuery += ` ORDER BY p.updated_at DESC`
		}
	case "name":
		baseQuery += fmt.Sprintf(` ORDER BY p.name %s`, order)
	case "created_at":
		baseQuery += fmt.Sprintf(` ORDER BY p.created_at %s`, order)
	case "updated_at":
		baseQuery += fmt.Sprintf(` ORDER BY p.updated_at %s`, order)
	case "activity":
		// Sort by recent activity (requires subquery for activity count)
		baseQuery = strings.Replace(baseQuery, "SELECT DISTINCT p.*,", `
			SELECT DISTINCT p.*,
				   COALESCE(activity_counts.activity_count, 0) as recent_activity,`, 1)
		baseQuery = strings.Replace(baseQuery, "FROM projects p", `
			FROM projects p
			LEFT JOIN (
				SELECT subject_id, COUNT(*) as activity_count
				FROM activity_logs 
				WHERE subject_type = 'Project' AND created_at >= ?
				GROUP BY subject_id
			) activity_counts ON p.id = activity_counts.subject_id`, 1)
		args = append([]interface{}{time.Now().AddDate(0, 0, -30)}, args...)
		baseQuery += fmt.Sprintf(` ORDER BY recent_activity %s, p.updated_at DESC`, order)
	default:
		baseQuery += ` ORDER BY p.updated_at DESC`
	}

	// Execute search query with pagination
	page := ctx.Request().InputInt("page", 1)
	perPage := ctx.Request().InputInt("per_page", 30)
	offset := (page - 1) * perPage

	baseQuery += ` LIMIT ? OFFSET ?`
	args = append(args, perPage, offset)

	type SearchResult struct {
		models.Project
		OrganizationName string `json:"organization_name"`
		OwnerName        string `json:"owner_name"`
		OwnerAvatar      string `json:"owner_avatar"`
		CanAccess        bool   `json:"can_access"`
		RelevanceScore   int    `json:"relevance_score"`
		RecentActivity   *int64 `json:"recent_activity,omitempty"`
	}

	var results []SearchResult
	if err := facades.Orm().Query().Raw(baseQuery, args...).Scan(&results); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to search projects: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Get total count for pagination
	countQuery := strings.Replace(baseQuery, "SELECT DISTINCT p.*,", "SELECT COUNT(DISTINCT p.id)", 1)
	countQuery = strings.Split(countQuery, "ORDER BY")[0] // Remove ORDER BY and LIMIT
	countQuery = strings.Split(countQuery, "LIMIT")[0]

	// Remove the last two arguments (LIMIT and OFFSET)
	countArgs := args[:len(args)-2]

	var totalCount int64
	facades.Orm().Query().Raw(countQuery, countArgs...).Scan(&totalCount)

	// Build response
	response := map[string]interface{}{
		"results": results,
		"search": map[string]interface{}{
			"query":       query,
			"total_count": totalCount,
			"filters": map[string]interface{}{
				"org_id":         orgID,
				"owner_id":       ownerID,
				"state":          state,
				"visibility":     visibility,
				"status":         status,
				"archived":       archived,
				"template":       template,
				"has_readme":     hasReadme,
				"created_after":  createdAfter,
				"created_before": createdBefore,
				"updated_after":  updatedAfter,
			},
			"sort": map[string]interface{}{
				"by":    sortBy,
				"order": order,
			},
		},
		"pagination": map[string]interface{}{
			"current_page": page,
			"per_page":     perPage,
			"total_pages":  (totalCount + int64(perPage) - 1) / int64(perPage),
			"total_count":  totalCount,
		},
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   fmt.Sprintf("Found %d projects", totalCount),
		Data:      response,
		Timestamp: time.Now(),
	})
}

// GetProjectRecommendations gets personalized project recommendations
// @Summary Get project recommendations
// @Description Get personalized project recommendations based on user activity and preferences
// @Tags project-search
// @Accept json
// @Produce json
// @Param type query string false "Recommendation type" Enums(recent,popular,similar,trending) default(recent)
// @Param limit query int false "Number of recommendations" minimum(1) maximum(50) default(10)
// @Success 200 {object} responses.APIResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /projects/recommendations [get]
func (psc *ProjectSearchController) GetProjectRecommendations(ctx http.Context) http.Response {
	userID := ctx.Value("user_id").(string)
	recommendationType := ctx.Request().Query("type", "recent")
	limit := ctx.Request().InputInt("limit", 10)

	if limit > 50 {
		limit = 50
	}

	var projects []models.Project
	var err error

	switch recommendationType {
	case "recent":
		// Recently active projects the user has access to
		err = facades.Orm().Query().Raw(`
			SELECT DISTINCT p.* FROM projects p
			LEFT JOIN user_organizations uo ON (p.organization_id = uo.organization_id AND uo.user_id = ? AND uo.is_active = true)
			LEFT JOIN activity_logs al ON (p.id = al.subject_id AND al.subject_type = 'Project')
			WHERE (p.owner_id = ? OR uo.user_id IS NOT NULL OR p.visibility = 'public')
			  AND p.is_archived = false
			  AND p.is_template = false
			  AND al.created_at >= ?
			ORDER BY al.created_at DESC
			LIMIT ?
		`, userID, userID, time.Now().AddDate(0, 0, -7), limit).Find(&projects)

	case "popular":
		// Most active projects in the last 30 days
		err = facades.Orm().Query().Raw(`
			SELECT p.*, activity_counts.activity_count FROM projects p
			LEFT JOIN user_organizations uo ON (p.organization_id = uo.organization_id AND uo.user_id = ? AND uo.is_active = true)
			LEFT JOIN (
				SELECT subject_id, COUNT(*) as activity_count
				FROM activity_logs 
				WHERE subject_type = 'Project' AND created_at >= ?
				GROUP BY subject_id
			) activity_counts ON p.id = activity_counts.subject_id
			WHERE (p.owner_id = ? OR uo.user_id IS NOT NULL OR p.visibility = 'public')
			  AND p.is_archived = false
			  AND p.is_template = false
			  AND activity_counts.activity_count > 0
			ORDER BY activity_counts.activity_count DESC
			LIMIT ?
		`, userID, time.Now().AddDate(0, 0, -30), userID, limit).Find(&projects)

	case "trending":
		// Projects with increasing activity trend
		err = facades.Orm().Query().Raw(`
			SELECT p.*, 
				   recent_activity.recent_count,
				   older_activity.older_count,
				   (recent_activity.recent_count::float / GREATEST(older_activity.older_count, 1)) as trend_score
			FROM projects p
			LEFT JOIN user_organizations uo ON (p.organization_id = uo.organization_id AND uo.user_id = ? AND uo.is_active = true)
			LEFT JOIN (
				SELECT subject_id, COUNT(*) as recent_count
				FROM activity_logs 
				WHERE subject_type = 'Project' AND created_at >= ?
				GROUP BY subject_id
			) recent_activity ON p.id = recent_activity.subject_id
			LEFT JOIN (
				SELECT subject_id, COUNT(*) as older_count
				FROM activity_logs 
				WHERE subject_type = 'Project' AND created_at >= ? AND created_at < ?
				GROUP BY subject_id
			) older_activity ON p.id = older_activity.subject_id
			WHERE (p.owner_id = ? OR uo.user_id IS NOT NULL OR p.visibility = 'public')
			  AND p.is_archived = false
			  AND p.is_template = false
			  AND recent_activity.recent_count > 0
			ORDER BY trend_score DESC, recent_activity.recent_count DESC
			LIMIT ?
		`, userID, time.Now().AddDate(0, 0, -7), time.Now().AddDate(0, 0, -14), time.Now().AddDate(0, 0, -7), userID, limit).Find(&projects)

	case "similar":
		// Projects similar to ones the user is active in
		err = facades.Orm().Query().Raw(`
			SELECT DISTINCT p2.* FROM projects p2
			LEFT JOIN user_organizations uo ON (p2.organization_id = uo.organization_id AND uo.user_id = ? AND uo.is_active = true)
			WHERE p2.id != ALL(
				SELECT DISTINCT p1.id FROM projects p1
				LEFT JOIN activity_logs al ON (p1.id = al.subject_id AND al.subject_type = 'Project' AND al.causer_id = ?)
				WHERE al.causer_id IS NOT NULL
			)
			AND (p2.owner_id = ? OR uo.user_id IS NOT NULL OR p2.visibility = 'public')
			AND p2.is_archived = false
			AND p2.is_template = false
			AND p2.organization_id IN (
				SELECT DISTINCT p1.organization_id FROM projects p1
				LEFT JOIN activity_logs al ON (p1.id = al.subject_id AND al.subject_type = 'Project' AND al.causer_id = ?)
				WHERE al.causer_id IS NOT NULL AND p1.organization_id IS NOT NULL
			)
			ORDER BY p2.updated_at DESC
			LIMIT ?
		`, userID, userID, userID, userID, limit).Find(&projects)

	default:
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid recommendation type. Must be one of: recent, popular, similar, trending",
			Timestamp: time.Now(),
		})
	}

	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to get project recommendations: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:  "success",
		Message: fmt.Sprintf("Retrieved %d %s project recommendations", len(projects), recommendationType),
		Data: map[string]interface{}{
			"type":         recommendationType,
			"projects":     projects,
			"count":        len(projects),
			"generated_at": time.Now(),
		},
		Timestamp: time.Now(),
	})
}

// GetProjectSuggestions gets search suggestions as user types
// @Summary Get project search suggestions
// @Description Get project search suggestions for autocomplete (GitHub Projects v2 style)
// @Tags project-search
// @Accept json
// @Produce json
// @Param q query string true "Search query (minimum 2 characters)"
// @Param limit query int false "Number of suggestions" minimum(1) maximum(20) default(10)
// @Success 200 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Router /projects/suggestions [get]
func (psc *ProjectSearchController) GetProjectSuggestions(ctx http.Context) http.Response {
	query := strings.TrimSpace(ctx.Request().Query("q", ""))
	limit := ctx.Request().InputInt("limit", 10)
	userID := ctx.Value("user_id").(string)

	if len(query) < 2 {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Search query must be at least 2 characters long",
			Timestamp: time.Now(),
		})
	}

	if limit > 20 {
		limit = 20
	}

	type Suggestion struct {
		ID               string `json:"id"`
		Name             string `json:"name"`
		Description      string `json:"description"`
		OrganizationName string `json:"organization_name"`
		OwnerName        string `json:"owner_name"`
		Visibility       string `json:"visibility"`
		State            string `json:"state"`
		Status           string `json:"status"`
		MatchType        string `json:"match_type"` // "name", "description", "owner", "organization"
	}

	var suggestions []Suggestion
	err := facades.Orm().Query().Raw(`
		SELECT p.id, p.name, p.description, p.visibility, p.state, p.status,
			   o.name as organization_name,
			   u.name as owner_name,
			   (CASE 
				   WHEN p.name ILIKE ? THEN 'name'
				   WHEN p.description ILIKE ? THEN 'description'
				   WHEN o.name ILIKE ? THEN 'organization'
				   WHEN u.name ILIKE ? THEN 'owner'
				   ELSE 'other'
			   END) as match_type
		FROM projects p
		LEFT JOIN organizations o ON p.organization_id = o.id
		LEFT JOIN users u ON p.owner_id = u.id
		LEFT JOIN user_organizations uo ON (p.organization_id = uo.organization_id AND uo.user_id = ? AND uo.is_active = true)
		WHERE (p.owner_id = ? OR uo.user_id IS NOT NULL OR p.visibility = 'public')
		  AND p.is_archived = false
		  AND p.is_template = false
		  AND (p.name ILIKE ? OR p.description ILIKE ? OR o.name ILIKE ? OR u.name ILIKE ?)
		ORDER BY 
		  (CASE 
			  WHEN p.name ILIKE ? THEN 1
			  WHEN p.description ILIKE ? THEN 2
			  WHEN o.name ILIKE ? THEN 3
			  WHEN u.name ILIKE ? THEN 4
			  ELSE 5
		  END),
		  p.updated_at DESC
		LIMIT ?
	`, "%"+query+"%", "%"+query+"%", "%"+query+"%", "%"+query+"%", userID, userID,
		"%"+query+"%", "%"+query+"%", "%"+query+"%", "%"+query+"%",
		"%"+query+"%", "%"+query+"%", "%"+query+"%", "%"+query+"%", limit).Scan(&suggestions)

	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to get project suggestions: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:  "success",
		Message: fmt.Sprintf("Retrieved %d project suggestions", len(suggestions)),
		Data: map[string]interface{}{
			"query":       query,
			"suggestions": suggestions,
			"count":       len(suggestions),
		},
		Timestamp: time.Now(),
	})
}

// GetProjectFilters gets available filter options for project search
// @Summary Get project search filters
// @Description Get available filter options and their counts for project search
// @Tags project-search
// @Accept json
// @Produce json
// @Success 200 {object} responses.APIResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /projects/filters [get]
func (psc *ProjectSearchController) GetProjectFilters(ctx http.Context) http.Response {
	userID := ctx.Value("user_id").(string)

	// Get filter counts
	type FilterCounts struct {
		States        map[string]int64       `json:"states"`
		Statuses      map[string]int64       `json:"statuses"`
		Visibilities  map[string]int64       `json:"visibilities"`
		Organizations map[string]interface{} `json:"organizations"`
		HasReadme     map[string]int64       `json:"has_readme"`
		IsTemplate    map[string]int64       `json:"is_template"`
		IsArchived    map[string]int64       `json:"is_archived"`
	}

	filters := FilterCounts{
		States:        make(map[string]int64),
		Statuses:      make(map[string]int64),
		Visibilities:  make(map[string]int64),
		Organizations: make(map[string]interface{}),
		HasReadme:     make(map[string]int64),
		IsTemplate:    make(map[string]int64),
		IsArchived:    make(map[string]int64),
	}

	// Get state counts
	type StateCount struct {
		State string `json:"state"`
		Count int64  `json:"count"`
	}
	var stateCounts []StateCount
	facades.Orm().Query().Raw(`
		SELECT p.state, COUNT(*) as count
		FROM projects p
		LEFT JOIN user_organizations uo ON (p.organization_id = uo.organization_id AND uo.user_id = ? AND uo.is_active = true)
		WHERE (p.owner_id = ? OR uo.user_id IS NOT NULL OR p.visibility = 'public')
		GROUP BY p.state
	`, userID, userID).Scan(&stateCounts)

	for _, sc := range stateCounts {
		filters.States[sc.State] = sc.Count
	}

	// Get status counts
	type StatusCount struct {
		Status string `json:"status"`
		Count  int64  `json:"count"`
	}
	var statusCounts []StatusCount
	facades.Orm().Query().Raw(`
		SELECT p.status, COUNT(*) as count
		FROM projects p
		LEFT JOIN user_organizations uo ON (p.organization_id = uo.organization_id AND uo.user_id = ? AND uo.is_active = true)
		WHERE (p.owner_id = ? OR uo.user_id IS NOT NULL OR p.visibility = 'public')
		GROUP BY p.status
	`, userID, userID).Scan(&statusCounts)

	for _, sc := range statusCounts {
		filters.Statuses[sc.Status] = sc.Count
	}

	// Get visibility counts
	type VisibilityCount struct {
		Visibility string `json:"visibility"`
		Count      int64  `json:"count"`
	}
	var visibilityCounts []VisibilityCount
	facades.Orm().Query().Raw(`
		SELECT p.visibility, COUNT(*) as count
		FROM projects p
		LEFT JOIN user_organizations uo ON (p.organization_id = uo.organization_id AND uo.user_id = ? AND uo.is_active = true)
		WHERE (p.owner_id = ? OR uo.user_id IS NOT NULL OR p.visibility = 'public')
		GROUP BY p.visibility
	`, userID, userID).Scan(&visibilityCounts)

	for _, vc := range visibilityCounts {
		filters.Visibilities[vc.Visibility] = vc.Count
	}

	// Get organization counts
	type OrgCount struct {
		ID    string `json:"id"`
		Name  string `json:"name"`
		Count int64  `json:"count"`
	}
	var orgCounts []OrgCount
	facades.Orm().Query().Raw(`
		SELECT o.id, o.name, COUNT(p.id) as count
		FROM organizations o
		JOIN projects p ON o.id = p.organization_id
		LEFT JOIN user_organizations uo ON (p.organization_id = uo.organization_id AND uo.user_id = ? AND uo.is_active = true)
		WHERE (p.owner_id = ? OR uo.user_id IS NOT NULL OR p.visibility = 'public')
		GROUP BY o.id, o.name
		ORDER BY count DESC, o.name
	`, userID, userID).Scan(&orgCounts)

	orgMap := make(map[string]interface{})
	for _, oc := range orgCounts {
		orgMap[oc.ID] = map[string]interface{}{
			"name":  oc.Name,
			"count": oc.Count,
		}
	}
	filters.Organizations = orgMap

	// Get boolean filter counts
	var readmeCount, templateCount, archivedCount int64

	facades.Orm().Query().Raw(`
		SELECT COUNT(*) FROM projects p
		LEFT JOIN user_organizations uo ON (p.organization_id = uo.organization_id AND uo.user_id = ? AND uo.is_active = true)
		WHERE (p.owner_id = ? OR uo.user_id IS NOT NULL OR p.visibility = 'public')
		  AND p.readme IS NOT NULL AND p.readme != ''
	`, userID, userID).Scan(&readmeCount)
	filters.HasReadme["true"] = readmeCount

	facades.Orm().Query().Raw(`
		SELECT COUNT(*) FROM projects p
		LEFT JOIN user_organizations uo ON (p.organization_id = uo.organization_id AND uo.user_id = ? AND uo.is_active = true)
		WHERE (p.owner_id = ? OR uo.user_id IS NOT NULL OR p.visibility = 'public')
		  AND p.is_template = true
	`, userID, userID).Scan(&templateCount)
	filters.IsTemplate["true"] = templateCount

	facades.Orm().Query().Raw(`
		SELECT COUNT(*) FROM projects p
		LEFT JOIN user_organizations uo ON (p.organization_id = uo.organization_id AND uo.user_id = ? AND uo.is_active = true)
		WHERE (p.owner_id = ? OR uo.user_id IS NOT NULL OR p.visibility = 'public')
		  AND p.is_archived = true
	`, userID, userID).Scan(&archivedCount)
	filters.IsArchived["true"] = archivedCount

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Project search filters retrieved successfully",
		Data:      filters,
		Timestamp: time.Now(),
	})
}
