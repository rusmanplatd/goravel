# OpenAPI 3.0 Documentation

This directory contains the auto-generated OpenAPI 3.0 specification for the Goravel API.

## Files

- `openapi.yaml` - OpenAPI 3.0 specification in YAML format
- `openapi.json` - OpenAPI 3.0 specification in JSON format
- `README.md` - This documentation file

## Auto-Generation

The OpenAPI specification is **dynamically generated** from the Go code using a sophisticated parser. The generator:

1. **Dynamically parses routes** from `routes/api.go` using AST analysis
2. **Automatically extracts models** from `app/models/` with field types and validation
3. **Parses request schemas** from `app/http/requests/` with validation rules
4. **Extracts response schemas** from `app/http/responses/` 
5. **Reads code annotations** and comments for descriptions and examples
6. **Generates comprehensive documentation** with proper OpenAPI 3.0 structure

## Generating Documentation

To regenerate the OpenAPI specification:

```bash
# Using the script
./scripts/generate-docs.sh

# Or directly with Go
go run scripts/generate-openapi.go
```

## Features Covered

The generated OpenAPI specification includes:

### Authentication
- JWT Bearer token authentication
- Security schemes for all protected endpoints

### User Management
- CRUD operations for users
- User-tenant relationships
- User-role assignments
- Pagination and search capabilities

### Tenant Management
- Multi-tenant organization support
- Tenant creation and management
- Tenant-user relationships

### Role-Based Access Control
- Role management within tenants
- Permission management
- Role-permission assignments
- User-role assignments

### Activity Logging
- Comprehensive activity tracking
- Filtering by log name, subject, and causer
- Date range filtering
- Pagination support

### Data Models
- Complete schema definitions for all models
- Request/response schemas
- Validation rules and examples
- Relationship mappings

### API Features
- Standardized response formats
- Error handling
- Pagination metadata
- Query parameters for filtering
- Path parameters for resource identification

## Viewing Documentation

Once the server is running, you can view the API documentation at:

- **Interactive UI**: http://localhost:8080/api/openapi.html
- **YAML Specification**: http://localhost:8080/api/docs/openapi.yaml
- **JSON Specification**: http://localhost:8080/api/docs/openapi.json

## Customization

The generator automatically adapts to your code changes. To modify the generated specification:

1. **Add new routes**: Simply add them to `routes/api.go` - they'll be automatically detected
2. **Add new models**: Create new structs in `app/models/` - they'll be automatically parsed
3. **Add new requests**: Create new request structs in `app/http/requests/` - they'll be automatically included
4. **Add new responses**: Create new response structs in `app/http/responses/` - they'll be automatically included
5. **Add annotations**: Use `@Description`, `@example`, and validation tags in your code
6. **Change metadata**: Modify the OpenAPI info, servers, or tags in the `main()` function

## Code Annotations

The generator automatically reads Go struct tags and comments for documentation:

```go
// User represents a user in the system
// @Description User model with multi-tenant support
type User struct {
    // User's full name
    // @example John Doe
    Name string `json:"name" binding:"required" example:"John Doe"`
    
    // User's email address
    // @example john.doe@example.com
    Email string `json:"email" binding:"required,email" example:"john.doe@example.com"`
    
    // User's password (write-only)
    // @example password123
    Password string `json:"password" binding:"required,min=8" example:"password123"`
}
```

### Supported Annotations

- `@Description` - Field or struct description
- `@example` - Example values
- `binding:"required"` - Required field validation
- `binding:"min=8"` - Minimum length validation
- `binding:"email"` - Email format validation
- `json:"field_name"` - JSON field name mapping

## Validation

The generated specification follows OpenAPI 3.0 standards and can be validated using:

- [Swagger Editor](https://editor.swagger.io/)
- [OpenAPI Validator](https://apitools.dev/openapi-validator/)
- Various OpenAPI tools and libraries 