package database

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/contracts/database/seeder"

	"goravel/database/migrations"
	"goravel/database/seeders"
)

type Kernel struct {
}

func (kernel Kernel) Migrations() []schema.Migration {
	return []schema.Migration{
		&migrations.M20210101000002CreateJobsTable{},
		&migrations.M20240915060148CreateUsersTable{},
		&migrations.M20250115000001CreateTenantsTable{},
		&migrations.M20250115000002CreateRolesTable{},
		&migrations.M20250115000003CreatePermissionsTable{},
		&migrations.M20250115000004CreateUserTenantsTable{},
		&migrations.M20250115000005CreateUserRolesTable{},
		&migrations.M20250115000006CreateRolePermissionsTable{},
		&migrations.M20250115000007CreateActivityLogsTable{},
		&migrations.M20250115000008AddAuthFieldsToUsersTable{},
		&migrations.M20250115000009CreateWebauthnCredentialsTable{},
		&migrations.M20250115000010CreatePasswordResetTokensTable{},
		&migrations.M20250115000011CreateOauthClientsTable{},
		&migrations.M20250115000012CreateOauthAccessTokensTable{},
		&migrations.M20250115000013CreateOauthRefreshTokensTable{},
		&migrations.M20250115000014CreateOauthAuthCodesTable{},
		&migrations.M20250115000015CreateOauthPersonalAccessClientsTable{},
		&migrations.M20250115000016CreateOauthDeviceCodesTable{},
		&migrations.M20250115000017CreateCountriesTable{},
		&migrations.M20250115000018CreateProvincesTable{},
		&migrations.M20250115000019CreateCitiesTable{},
		&migrations.M20250115000020CreateDistrictsTable{},
	}
}

func (kernel Kernel) Seeders() []seeder.Seeder {
	return []seeder.Seeder{
		&seeders.DatabaseSeeder{},
	}
}
