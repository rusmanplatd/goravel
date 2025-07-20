# Database Seeders

This directory contains database seeders for populating the application with initial data. The seeders are designed to create a complete development environment with users, roles, permissions, tenants, and sample data.

## Seeder Overview

### 1. DatabaseSeeder
The main seeder that orchestrates all other seeders in the correct order:
- OAuthSeeder
- RolePermissionSeeder
- TenantSeeder
- UserSeeder
- UserTenantSeeder
- ActivityLogSeeder
- GeographicSeeder

### 2. OAuthSeeder
Creates the OAuth personal access client for API authentication.

### 3. RolePermissionSeeder
Creates comprehensive roles and permissions:

#### Roles:
- **super-admin**: Full system access with all permissions
- **admin**: Tenant-level administrative access
- **manager**: Limited administrative access
- **user**: Basic user access
- **guest**: Read-only access

#### Permissions:
- **User Management**: view, create, edit, delete, export, import
- **Role Management**: view, create, edit, delete, assign
- **Permission Management**: view, create, edit, delete, assign
- **Tenant Management**: view, create, edit, delete, manage
- **Activity Logs**: view, export
- **Geographic Data**: view, manage for countries, provinces, cities, districts
- **System**: settings, backup, logs

### 4. TenantSeeder
Creates default tenants:
- **Goravel Corporation** (goravel-corp, goravel.com)
- **Demo Company** (demo-company, demo.com)
- **Test Organization** (test-org, test.org)

### 5. UserSeeder
Creates default users with different roles:
- **superadmin@goravel.com** (Super Administrator)
- **admin@goravel.com** (Admin User)
- **manager@goravel.com** (Manager User)
- **user@goravel.com** (Regular User)
- **test@goravel.com** (Test User)
- **guest@goravel.com** (Guest User)

All users have the password: `password123`

### 6. UserTenantSeeder
Assigns users to tenants with appropriate roles:

#### Goravel Corporation:
- superadmin (super-admin)
- admin (admin)
- manager (manager)
- user (user)
- guest (guest)

#### Demo Company:
- admin (admin)
- manager (manager)
- test (user)
- guest (guest)

#### Test Organization:
- manager (admin)
- user (user)

### 7. ActivityLogSeeder
Creates sample activity logs demonstrating the audit functionality:
- User login/logout events
- Profile updates
- User creation
- Tenant settings changes
- Role permission updates
- Permission creation
- Password changes
- MFA enablement
- Tenant creation

### 8. GeographicSeeder
Populates geographic data (countries, provinces, cities, districts).

## Running Seeders

### Run All Seeders
```bash
go run artisan.go db:seed
```

### Run Specific Seeder
```bash
go run artisan.go db:seed --class=UserSeeder
```

### Available Seeder Classes
- `DatabaseSeeder` (default)
- `OAuthSeeder`
- `RolePermissionSeeder`
- `TenantSeeder`
- `UserSeeder`
- `UserTenantSeeder`
- `ActivityLogSeeder`
- `GeographicSeeder`

## Development Workflow

1. **Fresh Installation**: Run all seeders to set up a complete development environment
2. **Testing**: Use the seeded data for testing different user roles and permissions
3. **Customization**: Modify seeders to add your own test data or modify existing data

## Security Notes

- Default passwords are set to `password123` for development purposes
- In production, ensure all users change their passwords
- The super-admin user has full system access
- Consider removing or securing sensitive seed data in production

## Multi-Tenant Structure

The seeders create a multi-tenant environment where:
- Users can belong to multiple tenants
- Roles are assigned per tenant
- Activity logs are tenant-scoped
- Permissions can be tenant-specific

## Testing with Seeded Data

### API Testing
Use the seeded users to test API endpoints:
- **Super Admin**: Full access to all endpoints
- **Admin**: Tenant-level administrative access
- **Manager**: Limited administrative access
- **User**: Basic user access
- **Guest**: Read-only access

### Authentication Testing
Test different authentication scenarios:
- Login with seeded users
- Test role-based access control
- Verify tenant isolation
- Test permission-based authorization

## Customization

To add custom seed data:

1. Create a new seeder file
2. Implement the `Signature()` and `Run()` methods
3. Add the seeder to `DatabaseSeeder.Run()`
4. Run the seeder with `go run artisan.go db:seed`

Example:
```go
type CustomSeeder struct{}

func (s *CustomSeeder) Signature() string {
    return "CustomSeeder"
}

func (s *CustomSeeder) Run() error {
    // Your seeding logic here
    return nil
}
``` 