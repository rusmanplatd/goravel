#!/bin/bash

# Validate OpenAPI 3.0 specification
echo "Validating OpenAPI 3.0 specification..."

# Check if files exist
if [ ! -f "docs/openapi.yaml" ]; then
    echo "Error: docs/openapi.yaml not found"
    exit 1
fi

if [ ! -f "docs/openapi.json" ]; then
    echo "Error: docs/openapi.json not found"
    exit 1
fi

# Basic validation checks
echo "Checking YAML syntax..."
if ! python3 -c "import yaml; yaml.safe_load(open('docs/openapi.yaml'))" 2>/dev/null; then
    echo "Error: Invalid YAML syntax in openapi.yaml"
    exit 1
fi

echo "Checking JSON syntax..."
if ! python3 -c "import json; json.load(open('docs/openapi.json'))" 2>/dev/null; then
    echo "Error: Invalid JSON syntax in openapi.json"
    exit 1
fi

# Check required OpenAPI fields
echo "Checking OpenAPI structure..."

# Check YAML
if ! grep -q "openapi: 3.0" docs/openapi.yaml; then
    echo "Error: Missing OpenAPI version in YAML"
    exit 1
fi

if ! grep -q "title:" docs/openapi.yaml; then
    echo "Error: Missing title in YAML"
    exit 1
fi

if ! grep -q "paths:" docs/openapi.yaml; then
    echo "Error: Missing paths in YAML"
    exit 1
fi

# Check JSON
if ! grep -q '"openapi": "3.0' docs/openapi.json; then
    echo "Error: Missing OpenAPI version in JSON"
    exit 1
fi

if ! grep -q '"title":' docs/openapi.json; then
    echo "Error: Missing title in JSON"
    exit 1
fi

if ! grep -q '"paths":' docs/openapi.json; then
    echo "Error: Missing paths in JSON"
    exit 1
fi

# Check for common endpoints
echo "Checking for common endpoints..."
if ! grep -q "/users" docs/openapi.yaml; then
    echo "Warning: Users endpoints not found in YAML"
fi

if ! grep -q "/organizations" docs/openapi.yaml; then
    echo "Warning: Organizations endpoints not found in YAML"
fi

if ! grep -q "/roles" docs/openapi.yaml; then
    echo "Warning: Roles endpoints not found in YAML"
fi

if ! grep -q "/permissions" docs/openapi.yaml; then
    echo "Warning: Permissions endpoints not found in YAML"
fi

# Check for schemas
echo "Checking for schemas..."
if ! grep -q "schemas:" docs/openapi.yaml; then
    echo "Warning: Schemas section not found in YAML"
fi

if ! grep -q "User:" docs/openapi.yaml; then
    echo "Warning: User schema not found in YAML"
fi

if ! grep -q "Organization:" docs/openapi.yaml; then
    echo "Warning: Organization schema not found in YAML"
fi

echo "OpenAPI 3.0 specification validation completed successfully!"
echo "Files are syntactically correct and contain required OpenAPI elements." 