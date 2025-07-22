#!/bin/bash

# Generate OpenAPI 3.0 documentation
echo "Generating OpenAPI 3.0 documentation..."

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo "Error: Go is not installed. Please install Go to generate OpenAPI documentation."
    exit 1a
fi

# Run the Go-based OpenAPI generator
echo "Running OpenAPI 3.0 generator..."
go run scripts/generate-openapi.go

# Validate the generated specification
echo "Validating generated specification..."
./scripts/validate-openapi.sh

echo "OpenAPI 3.0 documentation generated successfully!"
echo "You can view the API documentation at:"
echo "- OpenAPI 3.0 UI: http://localhost:3000/openapi.html"
echo "- OpenAPI 3.0 YAML: http://localhost:3000/api/docs/openapi.yaml"
echo "- OpenAPI 3.0 JSON: http://localhost:3000/api/docs/openapi.json" 