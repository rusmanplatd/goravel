package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// OpenAPI 3.0 specification structure
type OpenAPI struct {
	OpenAPI    string                `json:"openapi" yaml:"openapi"`
	Info       Info                  `json:"info" yaml:"info"`
	Servers    []Server              `json:"servers" yaml:"servers"`
	Paths      map[string]PathItem   `json:"paths" yaml:"paths"`
	Components Components            `json:"components" yaml:"components"`
	Security   []map[string][]string `json:"security" yaml:"security"`
	Tags       []Tag                 `json:"tags" yaml:"tags"`
}

type Info struct {
	Title       string  `json:"title" yaml:"title"`
	Description string  `json:"description" yaml:"description"`
	Version     string  `json:"version" yaml:"version"`
	Contact     Contact `json:"contact" yaml:"contact"`
}

type Contact struct {
	Name  string `json:"name" yaml:"name"`
	Email string `json:"email" yaml:"email"`
	URL   string `json:"url" yaml:"url"`
}

type Server struct {
	URL         string `json:"url" yaml:"url"`
	Description string `json:"description" yaml:"description"`
}

type PathItem struct {
	Get    *Operation `json:"get,omitempty" yaml:"get,omitempty"`
	Post   *Operation `json:"post,omitempty" yaml:"post,omitempty"`
	Put    *Operation `json:"put,omitempty" yaml:"put,omitempty"`
	Delete *Operation `json:"delete,omitempty" yaml:"delete,omitempty"`
	Patch  *Operation `json:"patch,omitempty" yaml:"patch,omitempty"`
}

type Operation struct {
	Tags        []string              `json:"tags" yaml:"tags"`
	Summary     string                `json:"summary" yaml:"summary"`
	Description string                `json:"description" yaml:"description"`
	OperationID string                `json:"operationId" yaml:"operationId"`
	Parameters  []Parameter           `json:"parameters,omitempty" yaml:"parameters,omitempty"`
	RequestBody *RequestBody          `json:"requestBody,omitempty" yaml:"requestBody,omitempty"`
	Responses   map[string]Response   `json:"responses" yaml:"responses"`
	Security    []map[string][]string `json:"security,omitempty" yaml:"security,omitempty"`
}

type Parameter struct {
	Name        string `json:"name" yaml:"name"`
	In          string `json:"in" yaml:"in"`
	Description string `json:"description" yaml:"description"`
	Required    bool   `json:"required" yaml:"required"`
	Schema      Schema `json:"schema" yaml:"schema"`
}

type RequestBody struct {
	Description string               `json:"description" yaml:"description"`
	Required    bool                 `json:"required" yaml:"required"`
	Content     map[string]MediaType `json:"content" yaml:"content"`
}

type MediaType struct {
	Schema Schema `json:"schema" yaml:"schema"`
}

type Response struct {
	Description string               `json:"description" yaml:"description"`
	Content     map[string]MediaType `json:"content,omitempty" yaml:"content,omitempty"`
}

type Schema struct {
	Type        string            `json:"type,omitempty" yaml:"type,omitempty"`
	Format      string            `json:"format,omitempty" yaml:"format,omitempty"`
	Description string            `json:"description,omitempty" yaml:"description,omitempty"`
	Example     interface{}       `json:"example,omitempty" yaml:"example,omitempty"`
	Properties  map[string]Schema `json:"properties,omitempty" yaml:"properties,omitempty"`
	Required    []string          `json:"required,omitempty" yaml:"required,omitempty"`
	Items       *Schema           `json:"items,omitempty" yaml:"items,omitempty"`
	Ref         string            `json:"$ref,omitempty" yaml:"$ref,omitempty"`
	AllOf       []Schema          `json:"allOf,omitempty" yaml:"allOf,omitempty"`
	MinLength   *int              `json:"minLength,omitempty" yaml:"minLength,omitempty"`
	MaxLength   *int              `json:"maxLength,omitempty" yaml:"maxLength,omitempty"`
	Pattern     string            `json:"pattern,omitempty" yaml:"pattern,omitempty"`
	Enum        []interface{}     `json:"enum,omitempty" yaml:"enum,omitempty"`
	Default     interface{}       `json:"default,omitempty" yaml:"default,omitempty"`
	Nullable    bool              `json:"nullable,omitempty" yaml:"nullable,omitempty"`
	ReadOnly    bool              `json:"readOnly,omitempty" yaml:"readOnly,omitempty"`
	WriteOnly   bool              `json:"writeOnly,omitempty" yaml:"writeOnly,omitempty"`
	Deprecated  bool              `json:"deprecated,omitempty" yaml:"deprecated,omitempty"`
}

type Components struct {
	Schemas         map[string]Schema         `json:"schemas,omitempty" yaml:"schemas,omitempty"`
	Responses       map[string]Response       `json:"responses,omitempty" yaml:"responses,omitempty"`
	Parameters      map[string]Parameter      `json:"parameters,omitempty" yaml:"parameters,omitempty"`
	RequestBodies   map[string]RequestBody    `json:"requestBodies,omitempty" yaml:"requestBodies,omitempty"`
	SecuritySchemes map[string]SecurityScheme `json:"securitySchemes,omitempty" yaml:"securitySchemes,omitempty"`
}

type SecurityScheme struct {
	Type         string `json:"type" yaml:"type"`
	Description  string `json:"description,omitempty" yaml:"description,omitempty"`
	Name         string `json:"name,omitempty" yaml:"name,omitempty"`
	In           string `json:"in,omitempty" yaml:"in,omitempty"`
	Scheme       string `json:"scheme,omitempty" yaml:"scheme,omitempty"`
	BearerFormat string `json:"bearerFormat,omitempty" yaml:"bearerFormat,omitempty"`
}

type Tag struct {
	Name        string `json:"name" yaml:"name"`
	Description string `json:"description" yaml:"description"`
}

// Parsed information structures
type RouteInfo struct {
	Method      string
	Path        string
	Handler     string
	Description string
	Parameters  []Parameter
	RequestBody *RequestBody
	Responses   map[string]Response
	Tags        []string
}

type StructInfo struct {
	Name        string
	Description string
	Properties  map[string]Schema
	Required    []string
	Package     string
}

type FieldInfo struct {
	Name        string
	Type        string
	Description string
	Example     interface{}
	Required    bool
	Validation  map[string]interface{}
}

// HandlerMethodInfo holds file and method name for a handler
type HandlerMethodInfo struct {
	FilePath   string
	MethodName string
}

// TagInfo holds tag name and description
type TagInfo struct {
	Name        string
	Description string
}

// CollectTagsFromControllers scans all controller files and collects unique tags and their descriptions
func CollectTagsFromControllers(controllerDir string) []Tag {
	tagMap := make(map[string]string)
	_ = filepath.Walk(controllerDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(path, ".go") {
			fset := token.NewFileSet()
			node, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
			if err != nil {
				return nil
			}
			ast.Inspect(node, func(n ast.Node) bool {
				fn, ok := n.(*ast.FuncDecl)
				if !ok || fn.Doc == nil {
					return true
				}
				var tagName, tagDesc string
				for _, comment := range fn.Doc.List {
					text := comment.Text
					if strings.Contains(text, "@Tags") {
						re := regexp.MustCompile(`@Tags\s+([\w\-, ]+)`)
						if matches := re.FindStringSubmatch(text); len(matches) > 1 {
							tagName = strings.TrimSpace(strings.Split(matches[1], ",")[0])
						}
					}
					if strings.Contains(text, "@TagDescription") {
						re := regexp.MustCompile(`@TagDescription\s+(.+)`)
						if matches := re.FindStringSubmatch(text); len(matches) > 1 {
							tagDesc = strings.TrimSpace(matches[1])
						}
					}
				}
				if tagName != "" {
					if tagDesc != "" {
						tagMap[tagName] = tagDesc
					} else if _, exists := tagMap[tagName]; !exists {
						tagMap[tagName] = ""
					}
				}
				return true
			})
		}
		return nil
	})
	tags := make([]Tag, 0, len(tagMap))
	for name, desc := range tagMap {
		tags = append(tags, Tag{Name: name, Description: desc})
	}
	return tags
}

func main() {
	fmt.Println("Generating OpenAPI 3.0 specification...")

	// Build the handler map once
	globalHandlerMap = BuildHandlerMethodMap("app/http/controllers/api/v1")

	// Collect tags dynamically
	dynamicTags := CollectTagsFromControllers("app/http/controllers/api/v1")

	// Initialize OpenAPI specification
	openAPI := &OpenAPI{
		OpenAPI: "3.0.3",
		Info: Info{
			Title:       "Goravel API",
			Description: "Multi-tenant API with role-based access control and activity logging",
			Version:     "1.0.0",
			Contact: Contact{
				Name:  "Goravel Team",
				Email: "support@goravel.com",
				URL:   "https://goravel.com",
			},
		},
		Servers: []Server{
			{
				URL:         "http://localhost:8080",
				Description: "Development server",
			},
			{
				URL:         "https://api.goravel.com",
				Description: "Production server",
			},
		},
		Paths:      make(map[string]PathItem),
		Components: Components{Schemas: make(map[string]Schema)},
		Security: []map[string][]string{
			{"bearerAuth": {}},
		},
		Tags: dynamicTags,
	}

	// Parse routes from API routes file
	fmt.Println("Parsing routes...")
	routes := parseRoutesFromFile("routes/api.go")

	// Parse models from model files
	fmt.Println("Parsing models...")
	models := parseModelsFromDirectory("app/models")

	// Parse request schemas
	fmt.Println("Parsing request schemas...")
	requests := parseRequestSchemas("app/http/requests")

	// Parse response schemas
	fmt.Println("Parsing response schemas...")
	responses := parseResponseSchemas("app/http/responses")

	// Build OpenAPI paths from routes
	fmt.Println("Building OpenAPI paths...")
	buildPaths(openAPI, routes)

	// Add schemas to components
	fmt.Println("Adding schemas...")
	addSchemas(openAPI, models, requests, responses)

	// Add security schemes
	addSecuritySchemes(openAPI)

	// Generate YAML file
	generateYAML(openAPI, "docs/openapi.yaml")

	// Generate JSON file
	generateJSON(openAPI, "docs/openapi.json")

	fmt.Println("OpenAPI 3.0 specification generated successfully!")
	fmt.Println("- YAML: docs/openapi.yaml")
	fmt.Println("- JSON: docs/openapi.json")
}

func parseRoutesFromFile(filename string) []RouteInfo {
	var routes []RouteInfo

	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, filename, nil, parser.ParseComments)
	if err != nil {
		fmt.Printf("Error parsing routes file: %v\n", err)
		return routes
	}

	// Extract route information from the AST
	ast.Inspect(node, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			route := extractRouteFromCall(call, fset)
			if route.Path != "" {
				routes = append(routes, route)
			}
		}
		return true
	})

	return routes
}

// extractOpenAPIDocFromController parses the controller file and extracts @Tags, @Summary, and @Description for a given method
func extractOpenAPIDocFromController(controllerFile, methodName string) (tags []string, summary, description string) {
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, controllerFile, nil, parser.ParseComments)
	if err != nil {
		return nil, "", ""
	}

	ast.Inspect(node, func(n ast.Node) bool {
		if fn, ok := n.(*ast.FuncDecl); ok && fn.Name.Name == methodName {
			if fn.Doc != nil {
				for _, comment := range fn.Doc.List {
					text := comment.Text
					if strings.Contains(text, "@Tags") {
						re := regexp.MustCompile(`@Tags\s+([\w\-, ]+)`)
						if matches := re.FindStringSubmatch(text); len(matches) > 1 {
							tags = strings.Split(strings.TrimSpace(matches[1]), ",")
							for i := range tags {
								tags[i] = strings.TrimSpace(tags[i])
							}
						}
					}
					if strings.Contains(text, "@Summary") {
						re := regexp.MustCompile(`@Summary\s+(.+)`)
						if matches := re.FindStringSubmatch(text); len(matches) > 1 {
							summary = strings.TrimSpace(matches[1])
						}
					}
					if strings.Contains(text, "@Description") {
						re := regexp.MustCompile(`@Description\s+(.+)`)
						if matches := re.FindStringSubmatch(text); len(matches) > 1 {
							description = strings.TrimSpace(matches[1])
						}
					}
				}
			}
			return false
		}
		return true
	})
	return
}

// extractRouteFromCall now uses the dynamic handler map
func extractRouteFromCall(call *ast.CallExpr, fset *token.FileSet) RouteInfo {
	route := RouteInfo{}

	// Check if this is a facades.Route().Method() call
	if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
		// Check if it's a method call on Route()
		if methodCall, ok := sel.X.(*ast.CallExpr); ok {
			if methodSel, ok := methodCall.Fun.(*ast.SelectorExpr); ok {
				if ident, ok := methodSel.X.(*ast.Ident); ok {
					if ident.Name == "facades" && methodSel.Sel.Name == "Route" {
						method := sel.Sel.Name
						route.Method = strings.ToUpper(method)

						// Extract path and handler from arguments
						if len(call.Args) >= 2 {
							if lit, ok := call.Args[0].(*ast.BasicLit); ok {
								route.Path = strings.Trim(lit.Value, "\"")
							}
							if sel, ok := call.Args[1].(*ast.SelectorExpr); ok {
								handlerStr := fmt.Sprintf("%s.%s", sel.X, sel.Sel.Name)
								route.Handler = handlerStr
								if info, ok := globalHandlerMap[handlerStr]; ok {
									tags, summary, description := extractOpenAPIDocFromController(info.FilePath, info.MethodName)
									if len(tags) > 0 {
										route.Tags = tags
									}
									if summary != "" {
										route.Description = summary
									}
									if description != "" {
										route.Description = description
									}
								}
							}
						}

						// Generate default responses
						route.Responses = generateDefaultResponses(route.Method, route.Path)

						// Generate parameters for path variables
						route.Parameters = extractPathParameters(route.Path)

						// Generate request body for POST/PUT operations
						if route.Method == "POST" || route.Method == "PUT" {
							route.RequestBody = generateRequestBody(route.Path, route.Method)
						}
					}
				}
			}
		}
	}

	return route
}

func extractDescriptionFromComments(node ast.Node, fset *token.FileSet) string {
	// Look for comments in the AST
	if node.Pos() > 0 {
		// This is a simplified approach - in practice you'd need more sophisticated comment parsing
		return "API endpoint"
	}
	return "API endpoint"
}

func generateDefaultResponses(method, path string) map[string]Response {
	responses := make(map[string]Response)

	switch method {
	case "GET":
		responses["200"] = Response{
			Description: "Success",
			Content: map[string]MediaType{
				"application/json": {Schema: Schema{Ref: "#/components/schemas/APIResponse"}},
			},
		}
		responses["401"] = Response{Description: "Unauthorized"}
		responses["403"] = Response{Description: "Forbidden"}
	case "POST":
		responses["201"] = Response{
			Description: "Created",
			Content: map[string]MediaType{
				"application/json": {Schema: Schema{Ref: "#/components/schemas/APIResponse"}},
			},
		}
		responses["400"] = Response{Description: "Bad request"}
		responses["422"] = Response{Description: "Validation error"}
	case "PUT":
		responses["200"] = Response{
			Description: "Updated",
			Content: map[string]MediaType{
				"application/json": {Schema: Schema{Ref: "#/components/schemas/APIResponse"}},
			},
		}
		responses["404"] = Response{Description: "Not found"}
		responses["422"] = Response{Description: "Validation error"}
	case "DELETE":
		responses["204"] = Response{Description: "Deleted"}
		responses["404"] = Response{Description: "Not found"}
	}

	return responses
}

func extractPathParameters(path string) []Parameter {
	var params []Parameter

	// Extract path parameters like {id}
	re := regexp.MustCompile(`\{([^}]+)\}`)
	matches := re.FindAllStringSubmatch(path, -1)

	for _, match := range matches {
		paramName := match[1]
		params = append(params, Parameter{
			Name:        paramName,
			In:          "path",
			Description: fmt.Sprintf("%s identifier", paramName),
			Required:    true,
			Schema:      Schema{Type: "string", Format: "ulid"},
		})
	}

	// Add common query parameters for list endpoints
	if strings.HasSuffix(path, "s") && !strings.Contains(path, "{") {
		params = append(params, Parameter{
			Name:        "cursor",
			In:          "query",
			Description: "Cursor for pagination",
			Required:    false,
			Schema:      Schema{Type: "string"},
		})
		params = append(params, Parameter{
			Name:        "limit",
			In:          "query",
			Description: "Items per page",
			Required:    false,
			Schema:      Schema{Type: "integer", Default: 10},
		})
	}

	return params
}

func generateRequestBody(path, method string) *RequestBody {
	// Determine request schema based on path and method
	var schemaRef string

	if strings.Contains(path, "/auth/login") {
		schemaRef = "#/components/schemas/LoginRequest"
	} else if strings.Contains(path, "/auth/register") {
		schemaRef = "#/components/schemas/RegisterRequest"
	} else if strings.Contains(path, "/auth/forgot-password") {
		schemaRef = "#/components/schemas/ForgotPasswordRequest"
	} else if strings.Contains(path, "/auth/reset-password") {
		schemaRef = "#/components/schemas/ResetPasswordRequest"
	} else if strings.Contains(path, "/auth/mfa/enable") {
		schemaRef = "#/components/schemas/EnableMfaRequest"
	} else if strings.Contains(path, "/auth/mfa/disable") {
		schemaRef = "#/components/schemas/DisableMfaRequest"
	} else if strings.Contains(path, "/auth/mfa/verify") {
		schemaRef = "#/components/schemas/VerifyMfaRequest"
	} else if strings.Contains(path, "/auth/webauthn/register") {
		schemaRef = "#/components/schemas/WebauthnRegisterRequest"
	} else if strings.Contains(path, "/auth/webauthn/authenticate") {
		schemaRef = "#/components/schemas/WebauthnAuthenticateRequest"
	} else if strings.Contains(path, "/auth/change-password") {
		schemaRef = "#/components/schemas/ChangePasswordRequest"
	} else if strings.Contains(path, "/auth/refresh") {
		schemaRef = "#/components/schemas/RefreshTokenRequest"
	} else if strings.Contains(path, "/users") {
		if method == "POST" {
			schemaRef = "#/components/schemas/CreateUserRequest"
		} else if method == "PUT" {
			schemaRef = "#/components/schemas/UpdateUserRequest"
		}
	} else if strings.Contains(path, "/tenants") {
		if method == "POST" {
			schemaRef = "#/components/schemas/CreateTenantRequest"
		}
	} else if strings.Contains(path, "/countries") {
		if method == "POST" {
			schemaRef = "#/components/schemas/CreateCountryRequest"
		} else if method == "PUT" {
			schemaRef = "#/components/schemas/UpdateCountryRequest"
		}
	} else if strings.Contains(path, "/provinces") {
		if method == "POST" {
			schemaRef = "#/components/schemas/CreateProvinceRequest"
		} else if method == "PUT" {
			schemaRef = "#/components/schemas/UpdateProvinceRequest"
		}
	} else if strings.Contains(path, "/cities") {
		if method == "POST" {
			schemaRef = "#/components/schemas/CreateCityRequest"
		} else if method == "PUT" {
			schemaRef = "#/components/schemas/UpdateCityRequest"
		}
	} else if strings.Contains(path, "/districts") {
		if method == "POST" {
			schemaRef = "#/components/schemas/CreateDistrictRequest"
		} else if method == "PUT" {
			schemaRef = "#/components/schemas/UpdateDistrictRequest"
		}
	}

	if schemaRef != "" {
		return &RequestBody{
			Description: "Request data",
			Required:    true,
			Content: map[string]MediaType{
				"application/json": {Schema: Schema{Ref: schemaRef}},
			},
		}
	}

	return nil
}

func parseModelsFromDirectory(dir string) map[string]StructInfo {
	models := make(map[string]StructInfo)

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && strings.HasSuffix(path, ".go") {
			fileModels := parseModelsFromFile(path)
			for name, model := range fileModels {
				models[name] = model
			}
		}
		return nil
	})

	if err != nil {
		fmt.Printf("Error walking models directory: %v\n", err)
	}

	return models
}

func parseModelsFromFile(filename string) map[string]StructInfo {
	models := make(map[string]StructInfo)

	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, filename, nil, parser.ParseComments)
	if err != nil {
		fmt.Printf("Error parsing model file %s: %v\n", filename, err)
		return models
	}

	ast.Inspect(node, func(n ast.Node) bool {
		if typeDecl, ok := n.(*ast.TypeSpec); ok {
			if structType, ok := typeDecl.Type.(*ast.StructType); ok {
				model := parseStructType(typeDecl, structType, fset)
				if model.Name != "" {
					models[model.Name] = model
				}
			}
		}
		return true
	})

	return models
}

func parseStructType(typeDecl *ast.TypeSpec, structType *ast.StructType, fset *token.FileSet) StructInfo {
	model := StructInfo{
		Name:       typeDecl.Name.Name,
		Properties: make(map[string]Schema),
		Required:   []string{},
	}

	// Extract description from comments
	model.Description = extractStructDescription(typeDecl, fset)

	// Parse struct fields
	for _, field := range structType.Fields.List {
		if len(field.Names) > 0 {
			fieldInfo := parseField(field, fset)

			if fieldInfo.Name != "" {
				model.Properties[fieldInfo.Name] = convertFieldToSchema(fieldInfo)
				if fieldInfo.Required {
					model.Required = append(model.Required, fieldInfo.Name)
				}
			}
		}
	}

	return model
}

func extractStructDescription(typeDecl *ast.TypeSpec, fset *token.FileSet) string {
	// Look for @Description comment
	if typeDecl.Doc != nil {
		for _, comment := range typeDecl.Doc.List {
			if strings.Contains(comment.Text, "@Description") {
				// Extract description from comment
				re := regexp.MustCompile(`@Description\s+(.+)`)
				if matches := re.FindStringSubmatch(comment.Text); len(matches) > 1 {
					return strings.TrimSpace(matches[1])
				}
			}
		}
	}

	// Fallback to struct name
	return fmt.Sprintf("%s model", typeDecl.Name.Name)
}

func parseField(field *ast.Field, fset *token.FileSet) FieldInfo {
	fieldInfo := FieldInfo{
		Name:        "",
		Type:        "",
		Description: "",
		Required:    false,
		Validation:  make(map[string]interface{}),
	}

	// Extract field name
	if len(field.Names) > 0 {
		fieldInfo.Name = field.Names[0].Name
	}

	// Extract field type
	fieldInfo.Type = extractFieldType(field.Type)

	// Extract description and validation from comments
	if field.Doc != nil {
		for _, comment := range field.Doc.List {
			text := comment.Text

			// Extract @Description
			if strings.Contains(text, "@Description") {
				re := regexp.MustCompile(`@Description\s+(.+)`)
				if matches := re.FindStringSubmatch(text); len(matches) > 1 {
					fieldInfo.Description = strings.TrimSpace(matches[1])
				}
			}

			// Extract @example
			if strings.Contains(text, "@example") {
				re := regexp.MustCompile(`@example\s+(.+)`)
				if matches := re.FindStringSubmatch(text); len(matches) > 1 {
					fieldInfo.Example = strings.TrimSpace(matches[1])
				}
			}

			// Extract validation tags
			if strings.Contains(text, "binding:") {
				re := regexp.MustCompile(`binding:"([^"]+)"`)
				if matches := re.FindStringSubmatch(text); len(matches) > 1 {
					validation := matches[1]
					if strings.Contains(validation, "required") {
						fieldInfo.Required = true
					}
					if strings.Contains(validation, "min=") {
						re := regexp.MustCompile(`min=(\d+)`)
						if matches := re.FindStringSubmatch(validation); len(matches) > 1 {
							fieldInfo.Validation["minLength"] = matches[1]
						}
					}
				}
			}
		}
	}

	// Extract validation from struct tags
	if field.Tag != nil {
		tag := strings.Trim(field.Tag.Value, "`")
		if strings.Contains(tag, "binding:") {
			re := regexp.MustCompile(`binding:"([^"]+)"`)
			if matches := re.FindStringSubmatch(tag); len(matches) > 1 {
				validation := matches[1]
				if strings.Contains(validation, "required") {
					fieldInfo.Required = true
				}
			}
		}
	}

	return fieldInfo
}

func extractFieldType(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return "*" + extractFieldType(t.X)
	case *ast.ArrayType:
		return "[]" + extractFieldType(t.Elt)
	case *ast.SelectorExpr:
		return fmt.Sprintf("%s.%s", extractFieldType(t.X), t.Sel.Name)
	default:
		return "interface{}"
	}
}

func convertFieldToSchema(field FieldInfo) Schema {
	schema := Schema{
		Description: field.Description,
		Example:     field.Example,
	}

	// Convert Go type to OpenAPI type
	switch field.Type {
	case "string":
		schema.Type = "string"
	case "int", "int64", "int32":
		schema.Type = "integer"
	case "float64", "float32":
		schema.Type = "number"
	case "bool":
		schema.Type = "boolean"
	case "time.Time":
		schema.Type = "string"
		schema.Format = "date-time"
	default:
		if strings.HasPrefix(field.Type, "[]") {
			schema.Type = "array"
			itemType := strings.TrimPrefix(field.Type, "[]")
			schema.Items = &Schema{Type: convertGoTypeToOpenAPIType(itemType)}
		} else if strings.HasPrefix(field.Type, "*") {
			schema.Type = convertGoTypeToOpenAPIType(strings.TrimPrefix(field.Type, "*"))
			schema.Nullable = true
		} else {
			schema.Type = "string"
		}
	}

	// Apply validation rules
	if minLength, ok := field.Validation["minLength"]; ok {
		if min, ok := minLength.(string); ok {
			if _, err := fmt.Sscanf(min, "%d", &schema.MinLength); err != nil {
				// Handle error
			}
		}
	}

	return schema
}

func convertGoTypeToOpenAPIType(goType string) string {
	switch goType {
	case "string":
		return "string"
	case "int", "int64", "int32":
		return "integer"
	case "float64", "float32":
		return "number"
	case "bool":
		return "boolean"
	case "time.Time":
		return "string"
	default:
		return "string"
	}
}

func parseRequestSchemas(dir string) map[string]Schema {
	schemas := make(map[string]Schema)

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && strings.HasSuffix(path, ".go") {
			fileSchemas := parseRequestSchemasFromFile(path)
			for name, schema := range fileSchemas {
				schemas[name] = schema
			}
		}
		return nil
	})

	if err != nil {
		fmt.Printf("Error walking requests directory: %v\n", err)
	}

	return schemas
}

func parseRequestSchemasFromFile(filename string) map[string]Schema {
	schemas := make(map[string]Schema)

	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, filename, nil, parser.ParseComments)
	if err != nil {
		fmt.Printf("Error parsing request file %s: %v\n", filename, err)
		return schemas
	}

	ast.Inspect(node, func(n ast.Node) bool {
		if typeDecl, ok := n.(*ast.TypeSpec); ok {
			if structType, ok := typeDecl.Type.(*ast.StructType); ok {
				if strings.Contains(typeDecl.Name.Name, "Request") {
					schema := convertStructToSchema(typeDecl, structType, fset)
					schemas[typeDecl.Name.Name] = schema
				}
			}
		}
		return true
	})

	return schemas
}

func parseResponseSchemas(dir string) map[string]Schema {
	schemas := make(map[string]Schema)

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && strings.HasSuffix(path, ".go") {
			fileSchemas := parseResponseSchemasFromFile(path)
			for name, schema := range fileSchemas {
				schemas[name] = schema
			}
		}
		return nil
	})

	if err != nil {
		fmt.Printf("Error walking responses directory: %v\n", err)
	}

	return schemas
}

func parseResponseSchemasFromFile(filename string) map[string]Schema {
	schemas := make(map[string]Schema)

	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, filename, nil, parser.ParseComments)
	if err != nil {
		fmt.Printf("Error parsing response file %s: %v\n", filename, err)
		return schemas
	}

	ast.Inspect(node, func(n ast.Node) bool {
		if typeDecl, ok := n.(*ast.TypeSpec); ok {
			if structType, ok := typeDecl.Type.(*ast.StructType); ok {
				if strings.Contains(typeDecl.Name.Name, "Response") {
					schema := convertStructToSchema(typeDecl, structType, fset)
					schemas[typeDecl.Name.Name] = schema
				}
			}
		}
		return true
	})

	return schemas
}

func convertStructToSchema(typeDecl *ast.TypeSpec, structType *ast.StructType, fset *token.FileSet) Schema {
	schema := Schema{
		Type:        "object",
		Description: extractStructDescription(typeDecl, fset),
		Properties:  make(map[string]Schema),
		Required:    []string{},
	}

	// Parse struct fields
	for _, field := range structType.Fields.List {
		if len(field.Names) > 0 {
			fieldInfo := parseField(field, fset)

			if fieldInfo.Name != "" {
				schema.Properties[fieldInfo.Name] = convertFieldToSchema(fieldInfo)
				if fieldInfo.Required {
					schema.Required = append(schema.Required, fieldInfo.Name)
				}
			}
		}
	}

	return schema
}

func requiresAuthentication(path string) bool {
	// Public endpoints that don't require authentication
	publicEndpoints := []string{
		"/api/v1/auth/login",
		"/api/v1/auth/register",
		"/api/v1/auth/forgot-password",
		"/api/v1/auth/reset-password",
		"/api/v1/auth/webauthn/authenticate",
		"/api/v1/oauth/token",
		"/api/v1/oauth/authorize",
		"/api/v1/oauth/introspect",
		"/api/v1/oauth/revoke",
		"/api/v1/oauth/device",
		"/api/v1/oauth/device/token",
		"/api/v1/oauth/device/complete",
		"/api/v1/oauth/token/exchange",
		"/api/docs",
		"/api/docs/openapi.yaml",
		"/api/docs/openapi.json",
		"/api/openapi.html",
	}

	for _, endpoint := range publicEndpoints {
		if path == endpoint {
			return false
		}
	}

	return true
}

func buildPaths(openAPI *OpenAPI, routes []RouteInfo) {
	for _, route := range routes {
		pathItem := openAPI.Paths[route.Path]

		operation := &Operation{
			Tags:        route.Tags,
			Summary:     route.Description,
			Description: route.Description,
			OperationID: generateOperationID(route.Method, route.Path),
			Parameters:  route.Parameters,
			RequestBody: route.RequestBody,
			Responses:   route.Responses,
		}

		// Add security requirement for protected endpoints
		if requiresAuthentication(route.Path) {
			operation.Security = []map[string][]string{
				{"bearerAuth": {}},
			}
		}

		switch route.Method {
		case "GET":
			pathItem.Get = operation
		case "POST":
			pathItem.Post = operation
		case "PUT":
			pathItem.Put = operation
		case "DELETE":
			pathItem.Delete = operation
		case "PATCH":
			pathItem.Patch = operation
		}

		openAPI.Paths[route.Path] = pathItem
	}
}

func addSchemas(openAPI *OpenAPI, models map[string]StructInfo, requests map[string]Schema, responses map[string]Schema) {
	// Add model schemas
	for name, model := range models {
		openAPI.Components.Schemas[name] = Schema{
			Type:        "object",
			Description: model.Description,
			Properties:  model.Properties,
			Required:    model.Required,
		}
	}

	// Add request schemas
	for name, schema := range requests {
		openAPI.Components.Schemas[name] = schema
	}

	// Add response schemas
	for name, schema := range responses {
		openAPI.Components.Schemas[name] = schema
	}

	// Add common response schemas if not already present
	if _, exists := openAPI.Components.Schemas["APIResponse"]; !exists {
		openAPI.Components.Schemas["APIResponse"] = Schema{
			Type:        "object",
			Description: "Standard API response format",
			Properties: map[string]Schema{
				"status": {
					Type:        "string",
					Description: "Response status",
					Example:     "success",
				},
				"message": {
					Type:        "string",
					Description: "Response message",
					Example:     "Operation completed successfully",
				},
				"data": {
					Type:        "object",
					Description: "Response data",
				},
				"timestamp": {
					Type:        "string",
					Format:      "date-time",
					Description: "Response timestamp",
					Example:     "2024-01-15T10:30:00Z",
				},
			},
			Required: []string{"status", "timestamp"},
		}
	}
}

func addSecuritySchemes(openAPI *OpenAPI) {
	openAPI.Components.SecuritySchemes = map[string]SecurityScheme{
		"bearerAuth": {
			Type:         "http",
			Scheme:       "bearer",
			BearerFormat: "JWT",
			Description:  "JWT token for API authentication",
		},
	}
}

func generateOperationID(method, path string) string {
	// Convert path to camelCase operation ID
	parts := strings.Split(strings.Trim(path, "/"), "/")
	var result []string

	for i, part := range parts {
		if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") {
			// Handle path parameters
			paramName := strings.Trim(part, "{}")
			if i == 0 {
				result = append(result, "get")
			}
			result = append(result, "by", strings.Title(paramName))
		} else {
			result = append(result, strings.Title(part))
		}
	}

	return strings.ToLower(method) + strings.Join(result, "")
}

func generateYAML(openAPI *OpenAPI, filename string) {
	data, err := yaml.Marshal(openAPI)
	if err != nil {
		fmt.Printf("Error marshaling YAML: %v\n", err)
		return
	}

	err = os.WriteFile(filename, data, 0644)
	if err != nil {
		fmt.Printf("Error writing YAML file: %v\n", err)
		return
	}
}

func generateJSON(openAPI *OpenAPI, filename string) {
	data, err := json.MarshalIndent(openAPI, "", "  ")
	if err != nil {
		fmt.Printf("Error marshaling JSON: %v\n", err)
		return
	}

	err = os.WriteFile(filename, data, 0644)
	if err != nil {
		fmt.Printf("Error writing JSON file: %v\n", err)
		return
	}
}

// BuildHandlerMethodMap scans all controller files and builds a map of handler string to file/method
func BuildHandlerMethodMap(controllerDir string) map[string]HandlerMethodInfo {
	handlerMap := make(map[string]HandlerMethodInfo)
	_ = filepath.Walk(controllerDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(path, ".go") {
			fset := token.NewFileSet()
			node, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
			if err != nil {
				return nil
			}
			ast.Inspect(node, func(n ast.Node) bool {
				fn, ok := n.(*ast.FuncDecl)
				if !ok || fn.Recv == nil || len(fn.Recv.List) == 0 {
					return true
				}
				// Get receiver name (e.g., (c *AuthController) -> c)
				recv := fn.Recv.List[0]
				var recvName string
				if len(recv.Names) > 0 {
					recvName = recv.Names[0].Name
				}
				if recvName != "" {
					handlerKey := fmt.Sprintf("%s.%s", recvName, fn.Name.Name)
					handlerMap[handlerKey] = HandlerMethodInfo{FilePath: path, MethodName: fn.Name.Name}
				}
				return true
			})
		}
		return nil
	})
	return handlerMap
}

// Declare global handler map
var globalHandlerMap map[string]HandlerMethodInfo
