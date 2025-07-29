package seeders

import (
	"errors"
	"fmt"
	"time"

	"github.com/goravel/framework/facades"

	"goravel/app/helpers"
	"goravel/app/models"
)

type RolePermissionSeeder struct {
}

// Signature The name and signature of the seeder.
func (s *RolePermissionSeeder) Signature() string {
	return "RolePermissionSeeder"
}

// Run executes the seeder logic.
func (s *RolePermissionSeeder) Run() error {
	facades.Log().Info(fmt.Sprintf("%s started", s.Signature()))
	defer facades.Log().Info(fmt.Sprintf("%s completed", s.Signature()))
	// Create default permissions
	permissions := []map[string]interface{}{
		// User permissions
		{"name": "users.view", "guard": "api", "description": "View users"},
		{"name": "users.create", "guard": "api", "description": "Create users"},
		{"name": "users.edit", "guard": "api", "description": "Edit users"},
		{"name": "users.delete", "guard": "api", "description": "Delete users"},
		{"name": "users.export", "guard": "api", "description": "Export users"},
		{"name": "users.import", "guard": "api", "description": "Import users"},

		// Role permissions
		{"name": "roles.view", "guard": "api", "description": "View roles"},
		{"name": "roles.create", "guard": "api", "description": "Create roles"},
		{"name": "roles.edit", "guard": "api", "description": "Edit roles"},
		{"name": "roles.delete", "guard": "api", "description": "Delete roles"},
		{"name": "roles.assign", "guard": "api", "description": "Assign roles to users"},

		// Permission permissions
		{"name": "permissions.view", "guard": "api", "description": "View permissions"},
		{"name": "permissions.create", "guard": "api", "description": "Create permissions"},
		{"name": "permissions.edit", "guard": "api", "description": "Edit permissions"},
		{"name": "permissions.delete", "guard": "api", "description": "Delete permissions"},
		{"name": "permissions.assign", "guard": "api", "description": "Assign permissions to roles"},

		// Organization permissions (expanded from organization permissions)
		{"name": "organizations.view", "guard": "api", "description": "View organizations"},
		{"name": "organizations.create", "guard": "api", "description": "Create organizations"},
		{"name": "organizations.edit", "guard": "api", "description": "Edit organizations"},
		{"name": "organizations.delete", "guard": "api", "description": "Delete organizations"},
		{"name": "organizations.manage", "guard": "api", "description": "Manage organizations"},

		// Activity log permissions
		{"name": "activity-logs.view", "guard": "api", "description": "View activity logs"},
		{"name": "activity-logs.export", "guard": "api", "description": "Export activity logs"},

		// Geographic permissions
		{"name": "countries.view", "guard": "api", "description": "View countries"},
		{"name": "countries.manage", "guard": "api", "description": "Manage countries"},
		{"name": "provinces.view", "guard": "api", "description": "View provinces"},
		{"name": "provinces.manage", "guard": "api", "description": "Manage provinces"},
		{"name": "cities.view", "guard": "api", "description": "View cities"},
		{"name": "cities.manage", "guard": "api", "description": "Manage cities"},
		{"name": "districts.view", "guard": "api", "description": "View districts"},
		{"name": "districts.manage", "guard": "api", "description": "Manage districts"},

		// System permissions
		{"name": "system.settings", "guard": "api", "description": "Manage system settings"},
		{"name": "system.backup", "guard": "api", "description": "Manage system backups"},
		{"name": "system.logs", "guard": "api", "description": "View system logs"},
	}

	userSeederULID := models.USER_SEEDER_ULID
	for _, permData := range permissions {
		var permission models.Permission
		err := facades.Orm().Query().Where("name = ? AND guard = ?", permData["name"], permData["guard"]).First(&permission)
		if err == nil && permission.ID != "" {
			// Permission already exists
			facades.Log().Info("RolePermissionSeeder: Permission already exists: " + permData["name"].(string))
		} else {
			// Permission doesn't exist, create it
			facades.Log().Info("RolePermissionSeeder: Creating permission: " + permData["name"].(string))
			permission = models.Permission{
				Name:        permData["name"].(string),
				Guard:       permData["guard"].(string),
				Description: permData["description"].(string),
				BaseModel: models.BaseModel{
					CreatedBy: &userSeederULID,
					UpdatedBy: &userSeederULID,
				},
			}

			// Debug log all ULID fields and their lengths
			facades.Log().Info("About to create permission", map[string]interface{}{
				"Name": permission.Name,
				"ID":   permission.ID, "ID_len": len(permission.ID),
				"CreatedBy": permission.CreatedBy, "CreatedBy_len": func() int {
					if permission.CreatedBy != nil {
						return len(*permission.CreatedBy)
					} else {
						return 0
					}
				}(),
				"UpdatedBy": permission.UpdatedBy, "UpdatedBy_len": func() int {
					if permission.UpdatedBy != nil {
						return len(*permission.UpdatedBy)
					} else {
						return 0
					}
				}(),
				"DeletedBy": permission.DeletedBy, "DeletedBy_len": func() int {
					if permission.DeletedBy != nil {
						return len(*permission.DeletedBy)
					} else {
						return 0
					}
				}(),
			})

			if permission.ID != "" && len(permission.ID) != 26 {
				facades.Log().Error("Permission ID length is not 26 characters", map[string]interface{}{"id": permission.ID, "length": len(permission.ID)})
				return errors.New("Permission ID length is not 26 characters")
			}
			if permission.CreatedBy != nil && len(*permission.CreatedBy) != 26 {
				facades.Log().Error("Permission CreatedBy length is not 26 characters", map[string]interface{}{"created_by": *permission.CreatedBy, "length": len(*permission.CreatedBy)})
				return errors.New("Permission CreatedBy length is not 26 characters")
			}
			if permission.UpdatedBy != nil && len(*permission.UpdatedBy) != 26 {
				facades.Log().Error("Permission UpdatedBy length is not 26 characters", map[string]interface{}{"updated_by": *permission.UpdatedBy, "length": len(*permission.UpdatedBy)})
				return errors.New("Permission UpdatedBy length is not 26 characters")
			}
			if permission.DeletedBy != nil && len(*permission.DeletedBy) != 26 {
				facades.Log().Error("Permission DeletedBy length is not 26 characters", map[string]interface{}{"deleted_by": *permission.DeletedBy, "length": len(*permission.DeletedBy)})
				return errors.New("Permission DeletedBy length is not 26 characters")
			}

			err = facades.Orm().Query().Create(&permission)
			if err != nil {
				facades.Log().Error("RolePermissionSeeder: Failed to create permission " + permData["name"].(string) + ": " + err.Error())
				return err
			}
			facades.Log().Info("RolePermissionSeeder: Successfully created permission: " + permData["name"].(string))
		}
	}

	// Create default roles
	roles := []map[string]interface{}{
		{
			"name":        "super-admin",
			"guard":       "api",
			"description": "Super Administrator with full access",
			"permissions": []string{
				// All permissions
				"users.view", "users.create", "users.edit", "users.delete", "users.export", "users.import",
				"roles.view", "roles.create", "roles.edit", "roles.delete", "roles.assign",
				"permissions.view", "permissions.create", "permissions.edit", "permissions.delete", "permissions.assign",
				"organizations.view", "organizations.create", "organizations.edit", "organizations.delete", "organizations.manage",
				"activity-logs.view", "activity-logs.export",
				"countries.view", "countries.manage",
				"provinces.view", "provinces.manage",
				"cities.view", "cities.manage",
				"districts.view", "districts.manage",
				"system.settings", "system.backup", "system.logs",
			},
		},
		{
			"name":        "admin",
			"guard":       "api",
			"description": "Administrator with organization-level access",
			"permissions": []string{
				"users.view", "users.create", "users.edit", "users.delete", "users.export",
				"roles.view", "roles.create", "roles.edit", "roles.assign",
				"permissions.view", "permissions.assign",
				"organizations.view", "organizations.edit",
				"activity-logs.view",
				"countries.view", "provinces.view", "cities.view", "districts.view",
			},
		},
		{
			"name":        "manager",
			"guard":       "api",
			"description": "Manager with limited administrative access",
			"permissions": []string{
				"users.view", "users.create", "users.edit",
				"roles.view", "roles.assign",
				"permissions.view",
				"activity-logs.view",
				"countries.view", "provinces.view", "cities.view", "districts.view",
			},
		},
		{
			"name":        "user",
			"guard":       "api",
			"description": "Regular user with basic access",
			"permissions": []string{
				"users.view",
				"countries.view", "provinces.view", "cities.view", "districts.view",
			},
		},
		{
			"name":        "guest",
			"guard":       "api",
			"description": "Guest user with read-only access",
			"permissions": []string{
				"countries.view", "provinces.view", "cities.view", "districts.view",
			},
		},
	}

	facades.Log().Info("RolePermissionSeeder: Starting to create roles...")
	for _, roleData := range roles {
		var role models.Role
		err := facades.Orm().Query().Where("name = ? AND guard = ?", roleData["name"], roleData["guard"]).First(&role)
		if err == nil && role.ID != "" {
			// Role already exists
			facades.Log().Info("RolePermissionSeeder: Role already exists: " + roleData["name"].(string))
		} else {
			// Role doesn't exist, create it
			facades.Log().Info("RolePermissionSeeder: Creating role: " + roleData["name"].(string))
			role = models.Role{
				Name:        roleData["name"].(string),
				Guard:       roleData["guard"].(string),
				Description: roleData["description"].(string),
				BaseModel: models.BaseModel{
					CreatedBy: &userSeederULID,
					UpdatedBy: &userSeederULID,
				},
			}
			err = facades.Orm().Query().Create(&role)
			if err != nil {
				facades.Log().Error("RolePermissionSeeder: Failed to create role " + roleData["name"].(string) + ": " + err.Error())
				return err
			}
			facades.Log().Info("RolePermissionSeeder: Successfully created role: " + roleData["name"].(string))

			// Assign permissions to role
			permissionNames := roleData["permissions"].([]string)
			for _, permName := range permissionNames {
				var permission models.Permission
				err = facades.Orm().Query().Where("name = ?", permName).First(&permission)
				if err == nil {
					// Debug: log role and permission IDs
					facades.Log().Info("Assigning permission to role:", map[string]interface{}{
						"role_name":       role.Name,
						"role_id":         role.ID,
						"permission_name": permission.Name,
						"permission_id":   permission.ID,
					})
					if len(role.ID) != 26 || len(permission.ID) != 26 || role.ID == "" || permission.ID == "" {
						facades.Log().Error("Invalid ULID length for role or permission", map[string]interface{}{
							"role_id":       role.ID,
							"permission_id": permission.ID,
						})
						continue
					}
					// Create role-permission relationship
					rolePerm := models.RolePermission{
						ID:           helpers.GenerateULID(),
						RoleID:       role.ID,
						PermissionID: permission.ID,
						CreatedAt:    time.Now(),
						UpdatedAt:    time.Now(),
					}
					err = facades.Orm().Query().Table("role_permissions").Create(&rolePerm)
					if err != nil {
						facades.Log().Error("RolePermissionSeeder: Failed to assign permission " + permName + " to role " + roleData["name"].(string) + ": " + err.Error())
						return err
					}
					facades.Log().Info("RolePermissionSeeder: Assigned permission " + permName + " to role " + roleData["name"].(string))
				} else {
					facades.Log().Warning("RolePermissionSeeder: Permission " + permName + " not found for role " + roleData["name"].(string))
				}
			}
		}
	}

	return nil
}
