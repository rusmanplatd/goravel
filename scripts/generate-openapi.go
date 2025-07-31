package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
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
	Deprecated  bool                  `json:"deprecated,omitempty" yaml:"deprecated,omitempty"`
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
	Minimum     *float64          `json:"minimum,omitempty" yaml:"minimum,omitempty"`
	Maximum     *float64          `json:"maximum,omitempty" yaml:"maximum,omitempty"`
}

type Components struct {
	Schemas         map[string]Schema         `json:"schemas,omitempty" yaml:"schemas,omitempty"`
	Responses       map[string]Response       `json:"responses,omitempty" yaml:"responses,omitempty"`
	Parameters      map[string]Parameter      `json:"parameters,omitempty" yaml:"parameters,omitempty"`
	RequestBodies   map[string]RequestBody    `json:"requestBodies,omitempty" yaml:"requestBodies,omitempty"`
	SecuritySchemes map[string]SecurityScheme `json:"securitySchemes,omitempty" yaml:"securitySchemes,omitempty"`
}

type SecurityScheme struct {
	Type         string                `json:"type" yaml:"type"`
	Description  string                `json:"description,omitempty" yaml:"description,omitempty"`
	Name         string                `json:"name,omitempty" yaml:"name,omitempty"`
	In           string                `json:"in,omitempty" yaml:"in,omitempty"`
	Scheme       string                `json:"scheme,omitempty" yaml:"scheme,omitempty"`
	BearerFormat string                `json:"bearerFormat,omitempty" yaml:"bearerFormat,omitempty"`
	Flows        map[string]OAuth2Flow `json:"flows,omitempty" yaml:"flows,omitempty"`
}

type OAuth2Flow struct {
	AuthorizationURL string            `json:"authorizationUrl,omitempty" yaml:"authorizationUrl,omitempty"`
	TokenURL         string            `json:"tokenUrl,omitempty" yaml:"tokenUrl,omitempty"`
	RefreshURL       string            `json:"refreshUrl,omitempty" yaml:"refreshUrl,omitempty"`
	Scopes           map[string]string `json:"scopes" yaml:"scopes"`
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
	Summary     string
	Description string
	Parameters  []Parameter
	RequestBody *RequestBody
	Responses   map[string]Response
	Tags        []string
	Security    []map[string][]string
	OperationID string
	Deprecated  bool
	IsPublic    bool
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

// AnnotationInfo holds parsed OpenAPI annotation data from controller methods
type AnnotationInfo struct {
	Summary     string
	Description string
	Tags        []string
	Parameters  []Parameter
	RequestBody *RequestBody
	Responses   map[string]Response
	Router      RouterInfo
	Accept      []string
	Produce     []string
	Security    []map[string][]string
	Deprecated  bool
	OperationID string
	IsPublic    bool
}

// RouterInfo holds parsed @Router annotation data
type RouterInfo struct {
	Path   string
	Method string
}

// QueryBuilderInfo holds information about querybuilder usage in a controller
type QueryBuilderInfo struct {
	UsesQueryBuilder bool
	AllowedFilters   []string
	AllowedSorts     []string
	AllowedIncludes  []string
	AllowedFields    []string
	HasPagination    bool
	PaginationType   string
	ModelType        string
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

// parseOpenAPIAnnotations extracts OpenAPI annotations from controller method comments
func parseOpenAPIAnnotations(controllerFile, methodName string) *AnnotationInfo {
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, controllerFile, nil, parser.ParseComments)
	if err != nil {
		return nil
	}

	var annotation *AnnotationInfo
	ast.Inspect(node, func(n ast.Node) bool {
		if fn, ok := n.(*ast.FuncDecl); ok && fn.Name.Name == methodName {
			if fn.Doc != nil {
				annotation = parseAnnotationsFromComments(fn.Doc.List)
			}
			return false
		}
		return true
	})
	return annotation
}

// parseAnnotationsFromComments parses OpenAPI annotations from comment lines
func parseAnnotationsFromComments(comments []*ast.Comment) *AnnotationInfo {
	annotation := &AnnotationInfo{
		Parameters: []Parameter{},
		Responses:  make(map[string]Response),
		Accept:     []string{},
		Produce:    []string{},
		Security:   []map[string][]string{},
	}

	fullComment := ""
	for _, comment := range comments {
		fullComment += comment.Text + "\n"
	}

	// Parse @Summary
	if re := regexp.MustCompile(`@Summary\s+(.+)`); re.MatchString(fullComment) {
		if matches := re.FindStringSubmatch(fullComment); len(matches) > 1 {
			annotation.Summary = strings.TrimSpace(matches[1])
		}
	}

	// Parse @Description (can be multi-line)
	if re := regexp.MustCompile(`@Description\s+([\s\S]*?)(?:@\w+|$)`); re.MatchString(fullComment) {
		if matches := re.FindStringSubmatch(fullComment); len(matches) > 1 {
			desc := strings.TrimSpace(matches[1])
			desc = strings.ReplaceAll(desc, "//", "")
			desc = strings.TrimSpace(desc)
			annotation.Description = desc
		}
	}

	// Parse @Tags
	if re := regexp.MustCompile(`@Tags\s+([\w\-, ]+)`); re.MatchString(fullComment) {
		if matches := re.FindStringSubmatch(fullComment); len(matches) > 1 {
			tags := strings.Split(strings.TrimSpace(matches[1]), ",")
			for i := range tags {
				tags[i] = strings.TrimSpace(tags[i])
			}
			annotation.Tags = tags
		}
	}

	// Parse @Accept (also supports @Consumes)
	acceptRe := regexp.MustCompile(`@(?:Accept|Consumes)\s+([\w\-, /]+)`)
	if acceptRe.MatchString(fullComment) {
		if matches := acceptRe.FindStringSubmatch(fullComment); len(matches) > 1 {
			accepts := strings.Split(strings.TrimSpace(matches[1]), ",")
			for i := range accepts {
				accepts[i] = strings.TrimSpace(accepts[i])
				if accepts[i] == "json" {
					accepts[i] = "application/json"
				} else if accepts[i] == "xml" {
					accepts[i] = "application/xml"
				} else if accepts[i] == "form" {
					accepts[i] = "application/x-www-form-urlencoded"
				} else if accepts[i] == "multipart" {
					accepts[i] = "multipart/form-data"
				}
			}
			annotation.Accept = accepts
		}
	}

	// Parse @Produce
	if re := regexp.MustCompile(`@Produce\s+([\w\-, /]+)`); re.MatchString(fullComment) {
		if matches := re.FindStringSubmatch(fullComment); len(matches) > 1 {
			produces := strings.Split(strings.TrimSpace(matches[1]), ",")
			for i := range produces {
				produces[i] = strings.TrimSpace(produces[i])
				if produces[i] == "json" {
					produces[i] = "application/json"
				} else if produces[i] == "xml" {
					produces[i] = "application/xml"
				} else if produces[i] == "html" {
					produces[i] = "text/html"
				} else if produces[i] == "plain" {
					produces[i] = "text/plain"
				}
			}
			annotation.Produce = produces
		}
	}

	// Parse @Security
	securityRe := regexp.MustCompile(`@Security\s+(\w+)(?:\s+\[([^\]]*)\])?`)
	securityMatches := securityRe.FindAllStringSubmatch(fullComment, -1)
	for _, match := range securityMatches {
		if len(match) >= 2 {
			securityScheme := strings.TrimSpace(match[1])
			var scopes []string
			if len(match) > 2 && match[2] != "" {
				scopes = strings.Split(strings.TrimSpace(match[2]), ",")
				for i := range scopes {
					scopes[i] = strings.TrimSpace(scopes[i])
				}
			}
			annotation.Security = append(annotation.Security, map[string][]string{
				securityScheme: scopes,
			})
		}
	}

	// Parse @Deprecated
	if strings.Contains(fullComment, "@Deprecated") || strings.Contains(fullComment, "@deprecated") {
		annotation.Deprecated = true
	}

	// Parse @Public (marks endpoint as not requiring authentication)
	if strings.Contains(fullComment, "@Public") || strings.Contains(fullComment, "@public") {
		annotation.IsPublic = true
	}

	// Parse @ID (operationId)
	if re := regexp.MustCompile(`@ID\s+(\w+)`); re.MatchString(fullComment) {
		if matches := re.FindStringSubmatch(fullComment); len(matches) > 1 {
			annotation.OperationID = strings.TrimSpace(matches[1])
		}
	}

	// Parse @Router
	if re := regexp.MustCompile(`@Router\s+([^\s]+)\s+\[(\w+)\]`); re.MatchString(fullComment) {
		if matches := re.FindStringSubmatch(fullComment); len(matches) > 2 {
			annotation.Router = RouterInfo{
				Path:   strings.TrimSpace(matches[1]),
				Method: strings.ToUpper(strings.TrimSpace(matches[2])),
			}
		}
	}

	// Parse @Param annotations with enhanced support
	paramRe := regexp.MustCompile(`@Param\s+(\w+)\s+(\w+)\s+(\w+)\s+(true|false)\s+"([^"]*)"(?:\s+(.+))?`)
	paramMatches := paramRe.FindAllStringSubmatch(fullComment, -1)
	for _, match := range paramMatches {
		if len(match) >= 6 {
			param := Parameter{
				Name:        match[1],
				In:          match[2],
				Description: match[5],
				Required:    match[4] == "true",
				Schema:      Schema{Type: match[3]},
			}

			// Parse additional schema properties from the optional part
			if len(match) > 6 && match[6] != "" {
				parseParameterExtras(&param, match[6])
			}

			annotation.Parameters = append(annotation.Parameters, param)
		}
	}

	// Parse @Success and @Failure annotations with enhanced support
	responseRe := regexp.MustCompile(`@(Success|Failure)\s+(\d+)\s+\{object\}\s+([^}\s]+(?:\{[^}]*\})?)\s*(?:"([^"]*)")?`)
	responseMatches := responseRe.FindAllStringSubmatch(fullComment, -1)
	for _, match := range responseMatches {
		if len(match) >= 4 {
			statusCode := match[2]
			schemaRef := match[3]
			description := "Success"
			if match[1] == "Failure" {
				description = "Error"
			}
			if len(match) > 4 && match[4] != "" {
				description = match[4]
			}

			// Convert schema reference to proper format
			if !strings.HasPrefix(schemaRef, "#/components/schemas/") {
				// Handle complex schema references like responses.APIResponse{data=models.User}
				if strings.Contains(schemaRef, "{") {
					// For now, use the base type
					schemaRef = strings.Split(schemaRef, "{")[0]
				}
				// Convert package.Type to just Type
				if strings.Contains(schemaRef, ".") {
					parts := strings.Split(schemaRef, ".")
					schemaRef = parts[len(parts)-1]
				}
				schemaRef = "#/components/schemas/" + schemaRef
			}

			response := Response{
				Description: description,
				Content: map[string]MediaType{
					"application/json": {
						Schema: Schema{Ref: schemaRef},
					},
				},
			}
			annotation.Responses[statusCode] = response
		}
	}

	// Parse request body from @Param with body type
	for _, param := range annotation.Parameters {
		if param.In == "body" {
			schemaRef := param.Schema.Type
			if !strings.HasPrefix(schemaRef, "#/components/schemas/") {
				// Convert package.Type to just Type
				if strings.Contains(schemaRef, ".") {
					parts := strings.Split(schemaRef, ".")
					schemaRef = parts[len(parts)-1]
				}
				schemaRef = "#/components/schemas/" + schemaRef
			}

			contentType := "application/json"
			if len(annotation.Accept) > 0 {
				contentType = annotation.Accept[0]
			}

			annotation.RequestBody = &RequestBody{
				Description: param.Description,
				Required:    param.Required,
				Content: map[string]MediaType{
					contentType: {
						Schema: Schema{Ref: schemaRef},
					},
				},
			}
			break
		}
	}

	// Remove body parameters from the parameters list since they're now in RequestBody
	filteredParams := []Parameter{}
	for _, param := range annotation.Parameters {
		if param.In != "body" {
			filteredParams = append(filteredParams, param)
		}
	}
	annotation.Parameters = filteredParams

	return annotation
}

// parseParameterExtras parses additional parameter properties like Enums, default, minimum, maximum
func parseParameterExtras(param *Parameter, extras string) {
	// Parse Enums
	if re := regexp.MustCompile(`Enums\(([^)]+)\)`); re.MatchString(extras) {
		if matches := re.FindStringSubmatch(extras); len(matches) > 1 {
			enumValues := strings.Split(matches[1], ",")
			param.Schema.Enum = make([]interface{}, len(enumValues))
			for i, val := range enumValues {
				param.Schema.Enum[i] = strings.TrimSpace(val)
			}
		}
	}

	// Parse default
	if re := regexp.MustCompile(`default\(([^)]+)\)`); re.MatchString(extras) {
		if matches := re.FindStringSubmatch(extras); len(matches) > 1 {
			defaultVal := strings.TrimSpace(matches[1])
			// Remove quotes if present
			defaultVal = strings.Trim(defaultVal, `"'`)
			if param.Schema.Type == "integer" {
				if intVal, err := strconv.Atoi(defaultVal); err == nil {
					param.Schema.Default = intVal
				}
			} else if param.Schema.Type == "number" {
				if floatVal, err := strconv.ParseFloat(defaultVal, 64); err == nil {
					param.Schema.Default = floatVal
				}
			} else if param.Schema.Type == "boolean" {
				param.Schema.Default = defaultVal == "true"
			} else {
				param.Schema.Default = defaultVal
			}
		}
	}

	// Parse minimum
	if re := regexp.MustCompile(`minimum\(([^)]+)\)`); re.MatchString(extras) {
		if matches := re.FindStringSubmatch(extras); len(matches) > 1 {
			if minVal, err := strconv.ParseFloat(strings.TrimSpace(matches[1]), 64); err == nil {
				param.Schema.Minimum = &minVal
			}
		}
	}

	// Parse maximum
	if re := regexp.MustCompile(`maximum\(([^)]+)\)`); re.MatchString(extras) {
		if matches := re.FindStringSubmatch(extras); len(matches) > 1 {
			if maxVal, err := strconv.ParseFloat(strings.TrimSpace(matches[1]), 64); err == nil {
				param.Schema.Maximum = &maxVal
			}
		}
	}

	// Parse example
	if re := regexp.MustCompile(`example\(([^)]+)\)`); re.MatchString(extras) {
		if matches := re.FindStringSubmatch(extras); len(matches) > 1 {
			exampleVal := strings.TrimSpace(matches[1])
			exampleVal = strings.Trim(exampleVal, `"'`)
			if param.Schema.Type == "integer" {
				if intVal, err := strconv.Atoi(exampleVal); err == nil {
					param.Schema.Example = intVal
				}
			} else if param.Schema.Type == "number" {
				if floatVal, err := strconv.ParseFloat(exampleVal, 64); err == nil {
					param.Schema.Example = floatVal
				}
			} else if param.Schema.Type == "boolean" {
				param.Schema.Example = exampleVal == "true"
			} else {
				param.Schema.Example = exampleVal
			}
		}
	}

	// Parse format for specific types
	if param.Schema.Type == "string" {
		if strings.Contains(extras, "format(date-time)") {
			param.Schema.Format = "date-time"
		} else if strings.Contains(extras, "format(date)") {
			param.Schema.Format = "date"
		} else if strings.Contains(extras, "format(email)") {
			param.Schema.Format = "email"
		} else if strings.Contains(extras, "format(uri)") {
			param.Schema.Format = "uri"
		} else if strings.Contains(extras, "format(ulid)") {
			param.Schema.Format = "ulid"
		} else if strings.Contains(extras, "format(uuid)") {
			param.Schema.Format = "uuid"
		} else if strings.Contains(extras, "format(password)") {
			param.Schema.Format = "password"
		} else if strings.Contains(extras, "format(binary)") {
			param.Schema.Format = "binary"
		} else if strings.Contains(extras, "format(byte)") {
			param.Schema.Format = "byte"
		}
	}

	// Parse collectionFormat for array parameters
	if param.Schema.Type == "array" || strings.Contains(extras, "collectionFormat") {
		if strings.Contains(extras, "collectionFormat(csv)") {
			// CSV is the default, no need to set anything special
		} else if strings.Contains(extras, "collectionFormat(ssv)") {
			// Space separated values
		} else if strings.Contains(extras, "collectionFormat(tsv)") {
			// Tab separated values
		} else if strings.Contains(extras, "collectionFormat(pipes)") {
			// Pipe separated values
		} else if strings.Contains(extras, "collectionFormat(multi)") {
			// Multiple parameter instances
		}
	}
}

func main() {
	log.Println("Starting OpenAPI 3.0 specification generation...")

	// Build the handler map once
	log.Println("Building handler method map from controllers...")
	globalHandlerMap = BuildHandlerMethodMap("app/http/controllers/api/v1")

	// Build variable-to-type map from routes file
	log.Println("Building variable-to-type map from routes file...")
	varTypeMap = buildVarTypeMap("routes/api.go")

	// Collect tags dynamically
	log.Println("Collecting tags dynamically from controllers...")
	dynamicTags := CollectTagsFromControllers("app/http/controllers/api/v1")

	// Initialize OpenAPI specification
	log.Println("Initializing OpenAPI specification structure...")
	openAPI := &OpenAPI{
		OpenAPI: "3.0.3",
		Info: Info{
			Title:       "Goravel API",
			Description: "Multi-organization API with role-based access control and activity logging",
			Version:     "1.0.0",
			Contact: Contact{
				Name:  "Goravel Team",
				Email: "support@goravel.com",
				URL:   "https://goravel.com",
			},
		},
		Servers: []Server{
			{
				URL:         "http://localhost:7000",
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
			{"BearerAuth": {}},
		},
		Tags: dynamicTags,
	}

	// Parse routes from API routes file
	log.Println("Parsing routes from API routes file...")
	routes := parseRoutesFromFile("routes/api.go")
	log.Printf("Found %d routes to process", len(routes))

	// Parse models from model files
	log.Println("Parsing models from model directory...")
	models := parseModelsFromDirectory("app/models")
	log.Printf("Found %d models to process", len(models))

	// Parse request schemas
	log.Println("Parsing request schemas from requests directory...")
	requests := parseRequestSchemas("app/http/requests")
	log.Printf("Found %d request schemas to process", len(requests))

	// Parse response schemas
	log.Println("Parsing response schemas from responses directory...")
	responses := parseResponseSchemas("app/http/responses")
	log.Printf("Found %d response schemas to process", len(responses))

	// Build OpenAPI paths from routes
	log.Println("Building OpenAPI paths from parsed routes...")
	buildPaths(openAPI, routes)

	// Ensure all used tags are present in openAPI.Tags
	usedTags := make(map[string]bool)
	for _, pathItem := range openAPI.Paths {
		for _, op := range []*Operation{pathItem.Get, pathItem.Post, pathItem.Put, pathItem.Delete, pathItem.Patch} {
			if op != nil {
				for _, tag := range op.Tags {
					usedTags[tag] = true
				}
			}
		}
	}
	existingTags := make(map[string]bool)
	for _, tag := range openAPI.Tags {
		existingTags[tag.Name] = true
	}
	for tag := range usedTags {
		if !existingTags[tag] {
			openAPI.Tags = append(openAPI.Tags, Tag{Name: tag, Description: ""})
		}
	}

	// Add schemas to components
	log.Println("Adding schemas to OpenAPI components...")
	addSchemas(openAPI, models, requests, responses)

	// Add security schemes
	log.Println("Adding security schemes to OpenAPI specification...")
	addSecuritySchemes(openAPI)

	// Generate YAML file
	log.Println("Generating YAML specification file...")
	generateYAML(openAPI, "docs/openapi.yaml")

	// Generate JSON file
	log.Println("Generating JSON specification file...")
	generateJSON(openAPI, "docs/openapi.json")

	log.Println("OpenAPI 3.0 specification generated successfully!")
	log.Println("Generated files:")
	log.Println("  - YAML: docs/openapi.yaml")
	log.Println("  - JSON: docs/openapi.json")
}

func parseRoutesFromFile(filename string) []RouteInfo {
	var routes []RouteInfo

	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, filename, nil, parser.ParseComments)
	if err != nil {
		log.Printf("Error parsing routes file: %v\n", err)
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

// extractRouteFromCall now uses dynamic annotation parsing instead of hardcoded mappings
func extractRouteFromCall(call *ast.CallExpr, fset *token.FileSet) RouteInfo {
	route := RouteInfo{}

	// Check if this is a method call (e.g., Get, Post, Put, Delete)
	if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
		method := sel.Sel.Name

		// Check if it's an HTTP method
		httpMethods := map[string]bool{
			"Get": true, "Post": true, "Put": true, "Delete": true, "Patch": true, "Options": true, "Head": true,
		}

		if httpMethods[method] {
			route.Method = strings.ToUpper(method)

			// Extract path and handler from arguments
			if len(call.Args) >= 2 {
				if lit, ok := call.Args[0].(*ast.BasicLit); ok {
					route.Path = strings.Trim(lit.Value, "\"")
				}

				// Handle different types of handler arguments
				switch handler := call.Args[1].(type) {
				case *ast.SelectorExpr:
					// Direct controller method: controllerVar.Method
					handlerTypeName := ""
					if ident, ok := handler.X.(*ast.Ident); ok {
						handlerTypeName = ident.Name
					}
					if realType, ok := varTypeMap[handlerTypeName]; ok {
						handlerTypeName = realType
					}
					handlerStr := fmt.Sprintf("%s.%s", handlerTypeName, handler.Sel.Name)
					route.Handler = handlerStr

					// Parse OpenAPI annotations from controller method
					if info, ok := globalHandlerMap[handlerStr]; ok {
						if annotation := parseOpenAPIAnnotations(info.FilePath, info.MethodName); annotation != nil {
							// Use annotation data if available
							if annotation.Summary != "" {
								route.Summary = annotation.Summary
							}
							if annotation.Description != "" {
								route.Description = annotation.Description
							}
							if len(annotation.Tags) > 0 {
								route.Tags = annotation.Tags
							}
							if len(annotation.Parameters) > 0 {
								route.Parameters = annotation.Parameters
							}
							if annotation.RequestBody != nil {
								route.RequestBody = annotation.RequestBody
							}
							if len(annotation.Responses) > 0 {
								route.Responses = annotation.Responses
							}
							if len(annotation.Security) > 0 {
								route.Security = annotation.Security
							}
							if annotation.OperationID != "" {
								route.OperationID = annotation.OperationID
							}
							if annotation.Deprecated {
								route.Deprecated = true
							}
							if annotation.IsPublic {
								route.IsPublic = true
							}

							// If @Router annotation specifies a different path/method, use it
							if annotation.Router.Path != "" && annotation.Router.Method != "" {
								route.Path = annotation.Router.Path
								route.Method = annotation.Router.Method
							}
						}
					}

					// Fallback to default generation if no annotations found
					if len(route.Parameters) == 0 {
						route.Parameters = extractPathParameters(route.Path)
					}
					if len(route.Responses) == 0 {
						route.Responses = generateDefaultResponses(route.Method, route.Path)
					}
					if route.RequestBody == nil && (route.Method == "POST" || route.Method == "PUT") {
						route.RequestBody = generateRequestBodyFromPath(route.Path, route.Method)
					}

				case *ast.FuncLit:
					// Inline function - skip for now
					return route
				}
			}
		}
	}

	// Fallback: if no tags, use first path segment after /api/v1/ as tag
	if len(route.Tags) == 0 && route.Path != "" {
		segments := strings.Split(strings.Trim(route.Path, "/"), "/")
		if len(segments) > 2 { // skip api/v1
			route.Tags = []string{segments[2]}
		} else if len(segments) > 0 {
			route.Tags = []string{segments[len(segments)-1]}
		} else {
			route.Tags = []string{"default"}
		}
	}

	return route
}

func extractDescriptionFromComments(node ast.Node, fset *token.FileSet) string {
	// Production-grade comment parsing for OpenAPI documentation

	// Get the position of the node
	pos := fset.Position(node.Pos())

	// Read the source file to extract comments
	sourceFile, err := ioutil.ReadFile(pos.Filename)
	if err != nil {
		return "API endpoint"
	}

	lines := strings.Split(string(sourceFile), "\n")
	if pos.Line <= 0 || pos.Line > len(lines) {
		return "API endpoint"
	}

	// Look for comments above the function
	var comments []string
	for i := pos.Line - 2; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if strings.HasPrefix(line, "//") {
			comment := strings.TrimPrefix(line, "//")
			comment = strings.TrimSpace(comment)

			// Skip common non-documentation comments
			if strings.HasPrefix(comment, "@") ||
				strings.HasPrefix(comment, "TODO") ||
				strings.HasPrefix(comment, "FIXME") ||
				strings.HasPrefix(comment, "nolint") {
				continue
			}

			// Check for OpenAPI/Swagger annotations
			if strings.HasPrefix(comment, "Summary:") {
				return strings.TrimSpace(strings.TrimPrefix(comment, "Summary:"))
			}
			if strings.HasPrefix(comment, "Description:") {
				return strings.TrimSpace(strings.TrimPrefix(comment, "Description:"))
			}

			// Collect regular comments
			if comment != "" {
				comments = append([]string{comment}, comments...)
			}
		} else if line != "" {
			// Stop at non-comment, non-empty line
			break
		}
	}

	// Join comments into description
	if len(comments) > 0 {
		description := strings.Join(comments, " ")
		// Clean up the description
		description = strings.ReplaceAll(description, "\n", " ")
		description = strings.ReplaceAll(description, "\t", " ")
		// Remove multiple spaces
		for strings.Contains(description, "  ") {
			description = strings.ReplaceAll(description, "  ", " ")
		}
		return strings.TrimSpace(description)
	}

	return "API endpoint"
}

func generateDefaultResponses(method, path string) map[string]Response {
	responses := make(map[string]Response)

	switch method {
	case "GET":
		// Check if this is a list endpoint (plural resource without ID)
		if strings.HasSuffix(path, "s") && !strings.Contains(path, "{") {
			// List endpoint with pagination
			responses["200"] = Response{
				Description: "Success",
				Content: map[string]MediaType{
					"application/json": {Schema: Schema{Ref: "#/components/schemas/PaginatedResponse"}},
				},
			}
		} else {
			// Single resource endpoint
			responses["200"] = Response{
				Description: "Success",
				Content: map[string]MediaType{
					"application/json": {Schema: Schema{Ref: "#/components/schemas/APIResponse"}},
				},
			}
		}
		responses["401"] = Response{Description: "Unauthorized"}
		responses["403"] = Response{Description: "Forbidden"}

		// Add 404 for single resource endpoints
		if strings.Contains(path, "{") {
			responses["404"] = Response{Description: "Not found"}
		}
	case "POST":
		responses["201"] = Response{
			Description: "Created",
			Content: map[string]MediaType{
				"application/json": {Schema: Schema{Ref: "#/components/schemas/APIResponse"}},
			},
		}
		responses["400"] = Response{Description: "Bad request"}
		responses["401"] = Response{Description: "Unauthorized"}
		responses["403"] = Response{Description: "Forbidden"}
		responses["422"] = Response{Description: "Validation error"}
	case "PUT":
		responses["200"] = Response{
			Description: "Updated",
			Content: map[string]MediaType{
				"application/json": {Schema: Schema{Ref: "#/components/schemas/APIResponse"}},
			},
		}
		responses["400"] = Response{Description: "Bad request"}
		responses["401"] = Response{Description: "Unauthorized"}
		responses["403"] = Response{Description: "Forbidden"}
		responses["404"] = Response{Description: "Not found"}
		responses["422"] = Response{Description: "Validation error"}
	case "DELETE":
		responses["204"] = Response{Description: "Deleted"}
		responses["401"] = Response{Description: "Unauthorized"}
		responses["403"] = Response{Description: "Forbidden"}
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

	return params
}

// generateRequestBodyFromPath provides fallback request body generation for paths without annotations
func generateRequestBodyFromPath(path, method string) *RequestBody {
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
	} else if strings.Contains(path, "/users") {
		if method == "POST" {
			schemaRef = "#/components/schemas/CreateUserRequest"
		} else if method == "PUT" {
			schemaRef = "#/components/schemas/UpdateUserRequest"
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
		log.Printf("Error walking models directory: %v\n", err)
	}

	return models
}

func parseModelsFromFile(filename string) map[string]StructInfo {
	models := make(map[string]StructInfo)

	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, filename, nil, parser.ParseComments)
	if err != nil {
		log.Printf("Error parsing model file %s: %v\n", filename, err)
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
		log.Printf("Error walking requests directory: %v\n", err)
	}

	return schemas
}

func parseRequestSchemasFromFile(filename string) map[string]Schema {
	schemas := make(map[string]Schema)

	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, filename, nil, parser.ParseComments)
	if err != nil {
		log.Printf("Error parsing request file %s: %v\n", filename, err)
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
		log.Printf("Error walking responses directory: %v\n", err)
	}

	return schemas
}

func parseResponseSchemasFromFile(filename string) map[string]Schema {
	schemas := make(map[string]Schema)

	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, filename, nil, parser.ParseComments)
	if err != nil {
		log.Printf("Error parsing response file %s: %v\n", filename, err)
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

// requiresAuthentication is now replaced by @Security annotations in controller methods
// This function serves as a fallback for routes without explicit security annotations
func requiresAuthenticationFallback(path string) bool {
	// Public endpoints that don't require authentication (fallback only)
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
		"/api/docs/openapi.html",
		"/api/docs/openapi.json",
		"/api/docs/openapi.yaml",
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

		// Use custom operationID if provided, otherwise generate one
		operationID := route.OperationID
		if operationID == "" {
			operationID = generateOperationID(route.Method, route.Path)
		}

		// Patch empty summary/description
		summary := route.Summary
		description := route.Description
		if strings.TrimSpace(summary) == "" {
			summary = operationID
		}
		if strings.TrimSpace(description) == "" {
			description = "API endpoint"
		}

		operation := &Operation{
			Tags:        route.Tags,
			Summary:     summary,
			Description: description,
			OperationID: operationID,
			Parameters:  route.Parameters,
			RequestBody: route.RequestBody,
			Responses:   route.Responses,
			Deprecated:  route.Deprecated,
		}

		// Handle security based on annotations
		if route.IsPublic {
			// Explicitly marked as public - no security required
			operation.Security = nil
		} else if len(route.Security) > 0 {
			// Use security from @Security annotations
			operation.Security = route.Security
		} else {
			// Smart default: if no explicit security annotation, check if it's a public endpoint
			// Authentication endpoints without @Security are assumed to be public
			isAuthEndpoint := strings.Contains(route.Path, "/auth/") &&
				(strings.Contains(route.Path, "/login") ||
					strings.Contains(route.Path, "/register") ||
					strings.Contains(route.Path, "/forgot-password") ||
					strings.Contains(route.Path, "/reset-password"))

			if isAuthEndpoint || !requiresAuthenticationFallback(route.Path) {
				// Public endpoint - no security required
				operation.Security = nil
			} else {
				// Default security for protected endpoints (fallback)
				operation.Security = []map[string][]string{
					{"BearerAuth": {}},
				}
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

	// Add paginated response schema
	if _, exists := openAPI.Components.Schemas["PaginatedResponse"]; !exists {
		openAPI.Components.Schemas["PaginatedResponse"] = Schema{
			Type:        "object",
			Description: "Paginated API response format with querybuilder support",
			Properties: map[string]Schema{
				"status": {
					Type:        "string",
					Description: "Response status",
					Example:     "success",
				},
				"message": {
					Type:        "string",
					Description: "Response message",
					Example:     "Data retrieved successfully",
				},
				"data": {
					Type:        "array",
					Description: "Array of items",
					Items: &Schema{
						Type:        "object",
						Description: "Resource item",
					},
				},
				"pagination": {
					Ref: "#/components/schemas/PaginationInfo",
				},
				"timestamp": {
					Type:        "string",
					Format:      "date-time",
					Description: "Response timestamp",
					Example:     "2024-01-15T10:30:00Z",
				},
			},
			Required: []string{"status", "data", "pagination", "timestamp"},
		}
	}

	// Add pagination info schema
	if _, exists := openAPI.Components.Schemas["PaginationInfo"]; !exists {
		openAPI.Components.Schemas["PaginationInfo"] = Schema{
			Type:        "object",
			Description: "Pagination metadata for querybuilder responses",
			Properties: map[string]Schema{
				"type": {
					Type:        "string",
					Description: "Type of pagination used",
					Enum:        []interface{}{"offset", "cursor"},
					Example:     "offset",
				},
				"count": {
					Type:        "integer",
					Description: "Number of items in current page",
					Example:     20,
				},
				"limit": {
					Type:        "integer",
					Description: "Maximum items per page",
					Example:     20,
				},
				"has_next": {
					Type:        "boolean",
					Description: "Whether there are more items after current page",
					Example:     true,
				},
				"has_prev": {
					Type:        "boolean",
					Description: "Whether there are items before current page",
					Example:     false,
				},
				// Offset pagination fields
				"current_page": {
					Type:        "integer",
					Description: "Current page number (offset pagination only)",
					Example:     1,
					Nullable:    true,
				},
				"last_page": {
					Type:        "integer",
					Description: "Last page number (offset pagination only)",
					Example:     5,
					Nullable:    true,
				},
				"per_page": {
					Type:        "integer",
					Description: "Items per page (offset pagination only)",
					Example:     20,
					Nullable:    true,
				},
				"total": {
					Type:        "integer",
					Description: "Total number of items (offset pagination only)",
					Example:     100,
					Nullable:    true,
				},
				"from": {
					Type:        "integer",
					Description: "Starting item number (offset pagination only)",
					Example:     1,
					Nullable:    true,
				},
				"to": {
					Type:        "integer",
					Description: "Ending item number (offset pagination only)",
					Example:     20,
					Nullable:    true,
				},
				// Cursor pagination fields
				"next_cursor": {
					Type:        "string",
					Description: "Cursor for next page (cursor pagination only)",
					Example:     "eyJpZCI6MTIzfQ==",
					Nullable:    true,
				},
				"prev_cursor": {
					Type:        "string",
					Description: "Cursor for previous page (cursor pagination only)",
					Example:     "eyJpZCI6MTAwfQ==",
					Nullable:    true,
				},
			},
			Required: []string{"type", "count", "limit", "has_next", "has_prev"},
		}
	}

	// Add filter group schema for complex filtering
	if _, exists := openAPI.Components.Schemas["FilterGroup"]; !exists {
		openAPI.Components.Schemas["FilterGroup"] = Schema{
			Type:        "object",
			Description: "Filter group for complex querybuilder filtering",
			Properties: map[string]Schema{
				"operator": {
					Type:        "string",
					Description: "Logical operator for combining conditions",
					Enum:        []interface{}{"AND", "OR"},
					Example:     "AND",
				},
				"conditions": {
					Type:        "array",
					Description: "Array of filter conditions",
					Items: &Schema{
						Ref: "#/components/schemas/FilterCondition",
					},
				},
				"groups": {
					Type:        "array",
					Description: "Nested filter groups",
					Items: &Schema{
						Ref: "#/components/schemas/FilterGroup",
					},
				},
			},
			Required: []string{"operator"},
		}
	}

	// Add filter condition schema
	if _, exists := openAPI.Components.Schemas["FilterCondition"]; !exists {
		openAPI.Components.Schemas["FilterCondition"] = Schema{
			Type:        "object",
			Description: "Individual filter condition for querybuilder",
			Properties: map[string]Schema{
				"field": {
					Type:        "string",
					Description: "Field name to filter on",
					Example:     "name",
				},
				"operator": {
					Type:        "string",
					Description: "Comparison operator",
					Enum:        []interface{}{"=", "!=", ">", ">=", "<", "<=", "LIKE", "NOT LIKE", "IN", "NOT IN", "BETWEEN", "IS NULL", "IS NOT NULL"},
					Example:     "LIKE",
				},
				"value": {
					Description: "Value to compare against",
					Example:     "%john%",
				},
			},
			Required: []string{"field", "operator"},
		}
	}
}

func addSecuritySchemes(openAPI *OpenAPI) {
	openAPI.Components.SecuritySchemes = map[string]SecurityScheme{
		"BearerAuth": {
			Type:         "http",
			Scheme:       "bearer",
			BearerFormat: "JWT",
			Description:  "JWT token for API authentication",
		},
		"apiKey": {
			Type:        "apiKey",
			Name:        "X-API-Key",
			In:          "header",
			Description: "API key for authentication",
		},
		"oauth2": {
			Type:        "oauth2",
			Description: "OAuth2 authentication",
			Flows: map[string]OAuth2Flow{
				"authorizationCode": {
					AuthorizationURL: "/oauth/authorize",
					TokenURL:         "/oauth/token",
					Scopes:           map[string]string{},
				},
				"clientCredentials": {
					TokenURL: "/oauth/token",
					Scopes:   map[string]string{},
				},
			},
		},
		"basicAuth": {
			Type:        "http",
			Scheme:      "basic",
			Description: "Basic HTTP authentication",
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
		log.Printf("Error marshaling YAML: %v\n", err)
		return
	}

	// Post-process YAML to fix quoting issues with operators
	yamlString := string(data)
	yamlString = fixYAMLOperatorQuoting(yamlString)

	err = os.WriteFile(filename, []byte(yamlString), 0644)
	if err != nil {
		log.Printf("Error writing YAML file: %v\n", err)
		return
	}
}

// fixYAMLOperatorQuoting fixes YAML quoting issues with comparison operators
func fixYAMLOperatorQuoting(yamlContent string) string {
	// Fix unquoted operators that have special meaning in YAML
	operators := []string{"=", "<", "<="}

	for _, op := range operators {
		// Pattern: "- " + operator at end of line (with proper indentation)
		pattern := regexp.MustCompile(`(?m)^(\s+- )` + regexp.QuoteMeta(op) + `$`)
		replacement := "${1}'" + op + "'"
		yamlContent = pattern.ReplaceAllString(yamlContent, replacement)
	}

	return yamlContent
}

func generateJSON(openAPI *OpenAPI, filename string) {
	data, err := json.MarshalIndent(openAPI, "", "  ")
	if err != nil {
		log.Printf("Error marshaling JSON: %v\n", err)
		return
	}

	err = os.WriteFile(filename, data, 0644)
	if err != nil {
		log.Printf("Error writing JSON file: %v\n", err)
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
				// Get receiver type name (e.g., (c *ProvinceController) -> ProvinceController)
				recv := fn.Recv.List[0]
				var typeName string
				switch t := recv.Type.(type) {
				case *ast.StarExpr:
					if ident, ok := t.X.(*ast.Ident); ok {
						typeName = ident.Name
					}
				case *ast.Ident:
					typeName = t.Name
				}
				if typeName != "" {
					handlerKey := fmt.Sprintf("%s.%s", typeName, fn.Name.Name)
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

var varTypeMap map[string]string

func buildVarTypeMap(filename string) map[string]string {
	m := make(map[string]string)
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, filename, nil, 0)
	if err != nil {
		return m
	}
	ast.Inspect(node, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			return true
		}
		ident, ok := assign.Lhs[0].(*ast.Ident)
		if !ok {
			return true
		}
		call, ok := assign.Rhs[0].(*ast.CallExpr)
		if !ok {
			return true
		}
		if fun, ok := call.Fun.(*ast.SelectorExpr); ok {
			// e.g., v1.NewProvinceController -> ProvinceController
			name := fun.Sel.Name
			if strings.HasPrefix(name, "New") && len(name) > 3 {
				typeName := name[3:]
				m[ident.Name] = typeName
			}
		}
		return true
	})
	return m
}
