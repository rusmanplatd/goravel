package seeders

import (
	"github.com/goravel/framework/facades"
)

type DatabaseSeeder struct {
}

// Signature The name and signature of the seeder.
func (s *DatabaseSeeder) Signature() string {
	return "DatabaseSeeder"
}

// Run executes the seeder logic.
func (s *DatabaseSeeder) Run() error {
	facades.Log().Info("Starting DatabaseSeeder...")

	// Run user seeder
	userSeeder := &UserSeeder{}
	err := userSeeder.Run()
	if err != nil {
		facades.Log().Error("Failed to run UserSeeder: " + err.Error())
		return err
	}

	// Run OAuth seeder first
	facades.Log().Info("Running OAuthSeeder...")
	oauthSeeder := &OAuthSeeder{}
	err = oauthSeeder.Run()
	if err != nil {
		facades.Log().Error("Failed to run OAuthSeeder: " + err.Error())
		return err
	}

	// Run OAuth client seeder
	oauthClientSeeder := &OAuthClientSeeder{}
	err = oauthClientSeeder.Run()
	if err != nil {
		facades.Log().Error("Failed to run OAuthClientSeeder: " + err.Error())
		return err
	}

	// Run role and permission seeder
	facades.Log().Info("About to run RolePermissionSeeder...")
	rolePermissionSeeder := &RolePermissionSeeder{}
	err = rolePermissionSeeder.Run()
	if err != nil {
		facades.Log().Error("Failed to run RolePermissionSeeder: " + err.Error())
		return err
	}
	facades.Log().Info("RolePermissionSeeder completed successfully")

	// Run tenant seeder
	tenantSeeder := &TenantSeeder{}
	err = tenantSeeder.Run()
	if err != nil {
		facades.Log().Error("Failed to run TenantSeeder: " + err.Error())
		return err
	}

	// Run user-tenant relationship seeder
	userTenantSeeder := &UserTenantSeeder{}
	err = userTenantSeeder.Run()
	if err != nil {
		facades.Log().Error("Failed to run UserTenantSeeder: " + err.Error())
		return err
	}

	// Run tenant-user relationship seeder
	tenantUserSeeder := &TenantUserSeeder{}
	err = tenantUserSeeder.Run()
	if err != nil {
		facades.Log().Error("Failed to run TenantUserSeeder: " + err.Error())
		return err
	}

	// Run activity log seeder
	activityLogSeeder := &ActivityLogSeeder{}
	err = activityLogSeeder.Run()
	if err != nil {
		facades.Log().Error("Failed to run ActivityLogSeeder: " + err.Error())
		return err
	}

	// Run country seeder
	countrySeeder := &CountrySeeder{}
	err = countrySeeder.Run()
	if err != nil {
		facades.Log().Error("Failed to run CountrySeeder: " + err.Error())
		return err
	}

	// Run province seeder
	provinceSeeder := &ProvinceSeeder{}
	err = provinceSeeder.Run()
	if err != nil {
		facades.Log().Error("Failed to run ProvinceSeeder: " + err.Error())
		return err
	}

	// Run city seeder
	citySeeder := &CitySeeder{}
	err = citySeeder.Run()
	if err != nil {
		facades.Log().Error("Failed to run CitySeeder: " + err.Error())
		return err
	}

	// Run district seeder
	districtSeeder := &DistrictSeeder{}
	err = districtSeeder.Run()
	if err != nil {
		facades.Log().Error("Failed to run DistrictSeeder: " + err.Error())
		return err
	}

	// Run WebAuthn credential seeder
	webauthnCredentialSeeder := &WebAuthnCredentialSeeder{}
	err = webauthnCredentialSeeder.Run()
	if err != nil {
		facades.Log().Error("Failed to run WebAuthnCredentialSeeder: " + err.Error())
		return err
	}

	// Run password reset token seeder
	passwordResetTokenSeeder := &PasswordResetTokenSeeder{}
	err = passwordResetTokenSeeder.Run()
	if err != nil {
		facades.Log().Error("Failed to run PasswordResetTokenSeeder: " + err.Error())
		return err
	}

	// Run OAuth device seeder
	oauthDeviceSeeder := &OAuthDeviceSeeder{}
	err = oauthDeviceSeeder.Run()
	if err != nil {
		facades.Log().Error("Failed to run OAuthDeviceSeeder: " + err.Error())
		return err
	}

	// Run OAuth personal access client seeder
	oauthPersonalAccessClientSeeder := &OAuthPersonalAccessClientSeeder{}
	err = oauthPersonalAccessClientSeeder.Run()
	if err != nil {
		facades.Log().Error("Failed to run OAuthPersonalAccessClientSeeder: " + err.Error())
		return err
	}

	// Run OAuth access token seeder
	oauthAccessTokenSeeder := &OAuthAccessTokenSeeder{}
	err = oauthAccessTokenSeeder.Run()
	if err != nil {
		facades.Log().Error("Failed to run OAuthAccessTokenSeeder: " + err.Error())
		return err
	}

	// Run OAuth auth code seeder
	oauthAuthCodeSeeder := &OAuthAuthCodeSeeder{}
	err = oauthAuthCodeSeeder.Run()
	if err != nil {
		facades.Log().Error("Failed to run OAuthAuthCodeSeeder: " + err.Error())
		return err
	}

	// Run OAuth refresh token seeder
	oauthRefreshTokenSeeder := &OAuthRefreshTokenSeeder{}
	err = oauthRefreshTokenSeeder.Run()
	if err != nil {
		facades.Log().Error("Failed to run OAuthRefreshTokenSeeder: " + err.Error())
		return err
	}

	// Run OAuth token seeder
	oauthTokenSeeder := &OAuthTokenSeeder{}
	err = oauthTokenSeeder.Run()
	if err != nil {
		facades.Log().Error("Failed to run OAuthTokenSeeder: " + err.Error())
		return err
	}

	// Run user role seeder
	userRoleSeeder := &UserRoleSeeder{}
	err = userRoleSeeder.Run()
	if err != nil {
		facades.Log().Error("Failed to run UserRoleSeeder: " + err.Error())
		return err
	}

	// Run chat seeder
	chatSeeder := &ChatSeeder{}
	err = chatSeeder.Run()
	if err != nil {
		facades.Log().Error("Failed to run ChatSeeder: " + err.Error())
		return err
	}

	// Run message thread seeder
	messageThreadSeeder := &MessageThreadSeeder{}
	err = messageThreadSeeder.Run()
	if err != nil {
		facades.Log().Error("Failed to run MessageThreadSeeder: " + err.Error())
		return err
	}

	// Run notification settings seeder
	notificationSettingsSeeder := &NotificationSettingsSeeder{}
	err = notificationSettingsSeeder.Run()
	if err != nil {
		facades.Log().Error("Failed to run NotificationSettingsSeeder: " + err.Error())
		return err
	}

	// Run calendar event seeder
	calendarEventSeeder := &CalendarEventSeeder{}
	err = calendarEventSeeder.Run()
	if err != nil {
		facades.Log().Error("Failed to run CalendarEventSeeder: " + err.Error())
		return err
	}

	// Run event reminder seeder
	eventReminderSeeder := &EventReminderSeeder{}
	err = eventReminderSeeder.Run()
	if err != nil {
		facades.Log().Error("Failed to run EventReminderSeeder: " + err.Error())
		return err
	}

	// Run department seeder
	departmentSeeder := &DepartmentSeeder{}
	err = departmentSeeder.Run()
	if err != nil {
		facades.Log().Error("Failed to run DepartmentSeeder: " + err.Error())
		return err
	}

	// Run team seeder
	teamSeeder := &TeamSeeder{}
	err = teamSeeder.Run()
	if err != nil {
		facades.Log().Error("Failed to run TeamSeeder: " + err.Error())
		return err
	}

	// Run project seeder
	projectSeeder := &ProjectSeeder{}
	err = projectSeeder.Run()
	if err != nil {
		facades.Log().Error("Failed to run ProjectSeeder: " + err.Error())
		return err
	}

	// Run user organization seeder
	userOrganizationSeeder := &UserOrganizationSeeder{}
	err = userOrganizationSeeder.Run()
	if err != nil {
		facades.Log().Error("Failed to run UserOrganizationSeeder: " + err.Error())
		return err
	}

	// Run user department seeder
	userDepartmentSeeder := &UserDepartmentSeeder{}
	err = userDepartmentSeeder.Run()
	if err != nil {
		facades.Log().Error("Failed to run UserDepartmentSeeder: " + err.Error())
		return err
	}

	// Run user team seeder
	userTeamSeeder := &UserTeamSeeder{}
	err = userTeamSeeder.Run()
	if err != nil {
		facades.Log().Error("Failed to run UserTeamSeeder: " + err.Error())
		return err
	}

	// Run user project seeder
	userProjectSeeder := &UserProjectSeeder{}
	err = userProjectSeeder.Run()
	if err != nil {
		facades.Log().Error("Failed to run UserProjectSeeder: " + err.Error())
		return err
	}

	// Run team project seeder
	teamProjectSeeder := &TeamProjectSeeder{}
	err = teamProjectSeeder.Run()
	if err != nil {
		facades.Log().Error("Failed to run TeamProjectSeeder: " + err.Error())
		return err
	}

	// Run task label seeder
	taskLabelSeeder := &TaskLabelSeeder{}
	err = taskLabelSeeder.Run()
	if err != nil {
		facades.Log().Error("Failed to run TaskLabelSeeder: " + err.Error())
		return err
	}

	// Run milestone seeder
	milestoneSeeder := &MilestoneSeeder{}
	err = milestoneSeeder.Run()
	if err != nil {
		facades.Log().Error("Failed to run MilestoneSeeder: " + err.Error())
		return err
	}

	// Run task board seeder
	taskBoardSeeder := &TaskBoardSeeder{}
	err = taskBoardSeeder.Run()
	if err != nil {
		facades.Log().Error("Failed to run TaskBoardSeeder: " + err.Error())
		return err
	}

	// Run task board column seeder
	taskBoardColumnSeeder := &TaskBoardColumnSeeder{}
	err = taskBoardColumnSeeder.Run()
	if err != nil {
		facades.Log().Error("Failed to run TaskBoardColumnSeeder: " + err.Error())
		return err
	}

	// Run push subscription seeder
	pushSubscriptionSeeder := &PushSubscriptionSeeder{}
	err = pushSubscriptionSeeder.Run()
	if err != nil {
		facades.Log().Error("Failed to run PushSubscriptionSeeder: " + err.Error())
		return err
	}

	// Run task seeder
	taskSeeder := &TaskSeeder{}
	err = taskSeeder.Run()
	if err != nil {
		facades.Log().Error("Failed to run TaskSeeder: " + err.Error())
		return err
	}

	facades.Log().Info("Database seeding completed successfully")
	return nil
}
