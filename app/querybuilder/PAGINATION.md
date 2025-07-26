# QueryBuilder Pagination Features

This document describes the pagination features available in the QueryBuilder package.

## Overview

The QueryBuilder supports three types of pagination with unified response structure:

1. **Offset-based Pagination** - Traditional page-based pagination with full count
2. **Simple Pagination** - Lightweight pagination without total count
3. **Cursor-based Pagination** - Efficient pagination for large datasets and real-time data
4. **Auto Pagination** - Dynamic type selection based on query parameters

All pagination methods return results with a consistent structure where pagination metadata is wrapped in a `pagination` object.

## Auto Pagination (Recommended)

The `AutoPaginate` method automatically chooses the pagination type based on query parameters.

### Basic Usage

```go
// In your controller
func GetUsers(ctx http.Context) {
    qb := querybuilder.For(&models.User{}).WithRequest(ctx)
    
    var users []models.User
    result, err := qb.AutoPaginate(&users)
    if err != nil {
        // handle error
    }
    
    ctx.Response().Json(200, result)
}
```

### URL Parameters
- `pagination_type` - Type of pagination: "offset" or "cursor" (default: from config)
- `page` - Page number for offset pagination (default: 1)
- `limit` - Items per page (default: 15, max: 100)
- `cursor` - Base64 encoded cursor for cursor pagination

Examples:
- Offset: `GET /users?pagination_type=offset&page=2&limit=20`
- Cursor: `GET /users?pagination_type=cursor&cursor=eyJpZCI6MTIzfQ==&limit=20`
- Default: `GET /users?limit=20` (uses default type from config)

### Response Structure
```json
{
  "data": [...],
  "pagination": {
    "type": "offset",
    "count": 20,
    "limit": 20,
    "has_next": true,
    "has_prev": false,
    "current_page": 1,
    "last_page": 5,
    "per_page": 20,
    "total": 100,
    "from": 1,
    "to": 20
  }
}
```

## Offset-based Pagination

### Basic Usage

```go
// In your controller
func GetUsers(ctx http.Context) {
    qb := querybuilder.For(&models.User{}).WithRequest(ctx)
    
    var users []models.User
    result, err := qb.OffsetPaginate(&users)
    if err != nil {
        // handle error
    }
    
    ctx.Response().Json(200, result)
}
```

### URL Parameters
- `page` - Page number (default: 1)
- `limit` - Items per page (default: 15, max: 100)

Example: `GET /users?page=2&limit=20`

### Response Structure
```json
{
  "data": [...],
  "pagination": {
    "type": "offset",
    "count": 20,
    "limit": 20,
    "has_next": true,
    "has_prev": true,
    "current_page": 2,
    "last_page": 5,
    "per_page": 20,
    "total": 100,
    "from": 21,
    "to": 40
  }
}
```

## Simple Pagination

Simple pagination is faster as it doesn't count total records.

### Basic Usage

```go
func GetUsers(ctx http.Context) {
    qb := querybuilder.For(&models.User{}).WithRequest(ctx)
    
    var users []models.User
    result, err := qb.SimplePaginate(&users)
    if err != nil {
        // handle error
    }
    
    ctx.Response().Json(200, result)
}
```

### Response Structure
```json
{
  "data": [...],
  "pagination": {
    "type": "simple",
    "count": 15,
    "limit": 15,
    "has_next": true,
    "has_prev": false,
    "current_page": 1,
    "last_page": -1,
    "per_page": 15,
    "total": -1,
    "from": 1,
    "to": 15
  }
}
```

Note: `total` and `last_page` are `-1` because they're not calculated.

## Cursor-based Pagination

Cursor-based pagination is ideal for:
- Large datasets
- Real-time data where new records are frequently added
- Better performance for deep pagination
- Consistent results even when data changes

### Basic Usage

```go
func GetUsers(ctx http.Context) {
    qb := querybuilder.For(&models.User{}).WithRequest(ctx)
    
    var users []models.User
    result, err := qb.CursorPaginate(&users)
    if err != nil {
        // handle error
    }
    
    ctx.Response().Json(200, result)
}
```

### URL Parameters
- `cursor` - Base64 encoded cursor for pagination
- `limit` - Items per page (default: 15, max: 100)
- `reverse` - Set to "true" for reverse pagination

Examples:
- First page: `GET /users?limit=20`
- Next page: `GET /users?cursor=eyJpZCI6MTIzLCJjcmVhdGVkX2F0IjoiMjAyNC0wMS0wMVQwMDowMDowMFoifQ==&limit=20`
- Previous page: `GET /users?cursor=...&reverse=true&limit=20`

### Response Structure
```json
{
  "data": [...],
  "pagination": {
    "type": "cursor",
    "count": 20,
    "limit": 20,
    "has_next": true,
    "has_prev": false,
    "next_cursor": "eyJpZCI6MTIzLCJjcmVhdGVkX2F0IjoiMjAyNC0wMS0wMVQwMDowMDowMFoifQ==",
    "prev_cursor": null
  }
}
```

### Custom Cursor Fields

By default, cursor pagination uses `created_at` and `id` fields. You can customize this:

```go
func GetUsers(ctx http.Context) {
    options := querybuilder.PaginationOptions{
        CursorFields: []querybuilder.CursorField{
            {Name: "updated_at", Direction: "desc"},
            {Name: "id", Direction: "desc"},
        },
    }
    
    qb := querybuilder.For(&models.User{}).WithRequest(ctx)
    
    var users []models.User
    result, err := qb.CursorPaginate(&users, options)
    // ...
}
```

## Manual Pagination

You can use pagination without HTTP request context:

```go
// Manual offset pagination
qb := querybuilder.For(&models.User{})
var users []models.User
result, err := qb.PaginateWithResult(1, 10, &users) // page 1, 10 items

// Manual cursor pagination
options := querybuilder.PaginationOptions{
    CursorFields: []querybuilder.CursorField{
        {Name: "id", Direction: "asc"},
    },
}
result, err := qb.CursorPaginate(&users, options)
```

## Custom Configuration

You can customize pagination parameters:

```go
paginationConfig := &querybuilder.PaginationConfig{
    Type:            querybuilder.PaginationTypeOffset,
    DefaultLimit:    20,
    MaxLimit:        100,
    PageParameter:   "p",        // Use 'p' instead of 'page'
    LimitParameter:  "per_page", // Use 'per_page' instead of 'limit'
    CursorParameter: "cursor",
    TypeParameter:   "type",     // Use 'type' instead of 'pagination_type'
}

qb := querybuilder.For(&models.User{}).
    WithRequest(ctx).
    WithPaginationConfig(paginationConfig)

var users []models.User
result, err := qb.AutoPaginate(&users)
```

Now URLs would use: `GET /users?type=cursor&cursor=abc&per_page=20`

## Combining with Filters and Sorts

Pagination works seamlessly with other QueryBuilder features:

```go
qb := querybuilder.For(&models.User{}).
    WithRequest(ctx).
    AllowedFilters("name", "email", querybuilder.Exact("status")).
    AllowedSorts("name", "created_at").
    DefaultSort("-created_at")

var users []models.User
result, err := qb.AutoPaginate(&users)
```

Example URL: `GET /users?filter[name]=john&sort=-created_at&pagination_type=offset&page=2&limit=10`

## Unified Response Structure

All pagination methods return a consistent structure:

```go
type UnifiedPaginationResult struct {
    Data       interface{}     `json:"data"`
    Pagination *PaginationInfo `json:"pagination"`
}

type PaginationInfo struct {
    // Common fields for all pagination types
    Count   int    `json:"count"`
    Limit   int    `json:"limit"`
    HasNext bool   `json:"has_next"`
    HasPrev bool   `json:"has_prev"`
    Type    string `json:"type"` // "offset", "cursor", or "simple"

    // Offset pagination specific fields (nil for cursor pagination)
    CurrentPage *int   `json:"current_page,omitempty"`
    LastPage    *int   `json:"last_page,omitempty"`
    PerPage     *int   `json:"per_page,omitempty"`
    Total       *int64 `json:"total,omitempty"`
    From        *int   `json:"from,omitempty"`
    To          *int   `json:"to,omitempty"`

    // Cursor pagination specific fields (nil for offset pagination)
    NextCursor *string `json:"next_cursor,omitempty"`
    PrevCursor *string `json:"prev_cursor,omitempty"`
}
```

## Performance Considerations

### Offset Pagination
- **Pros**: Easy to implement, shows total count, allows jumping to any page
- **Cons**: Slower for large offsets, inconsistent results if data changes during pagination

### Simple Pagination
- **Pros**: Faster than offset pagination (no count query)
- **Cons**: No total count, can't jump to specific pages

### Cursor Pagination
- **Pros**: Consistent performance regardless of dataset size, stable results even with data changes
- **Cons**: Can't jump to arbitrary pages, more complex to implement

### Auto Pagination
- **Pros**: Flexible, allows clients to choose optimal pagination type
- **Cons**: Slightly more complex API surface

## Best Practices

1. **Use AutoPaginate** for maximum flexibility
2. **Use cursor pagination** for large datasets or real-time data
3. **Use simple pagination** when you don't need total counts
4. **Use offset pagination** for traditional page-based navigation with page numbers
5. **Set reasonable limits** to prevent performance issues
6. **Index cursor fields** in your database for optimal performance
7. **Use composite cursors** (multiple fields) for better uniqueness

## Migration from Legacy Pagination

The old `Paginate` method is still available but deprecated:

```go
// Old way (still works)
err := qb.Paginate(1, 10, &users)

// New way
result, err := qb.PaginateWithResult(1, 10, &users)
// or
result, err := qb.AutoPaginate(&users) // with request context
```

## Examples

### E-commerce Product Listing
```go
// Products with filters and auto pagination
qb := querybuilder.For(&models.Product{}).
    WithRequest(ctx).
    AllowedFilters("category", "brand", querybuilder.Between("price")).
    AllowedSorts("name", "price", "created_at").
    DefaultSort("name")

var products []models.Product
result, err := qb.AutoPaginate(&products)
```

URL: `GET /products?filter[category]=electronics&filter[price]=100,500&sort=price&pagination_type=offset&page=1&limit=20`

### Real-time Chat Messages
```go
// Use cursor pagination for chat messages
options := querybuilder.PaginationOptions{
    CursorFields: []querybuilder.CursorField{
        {Name: "created_at", Direction: "desc"},
        {Name: "id", Direction: "desc"},
    },
}

qb := querybuilder.For(&models.Message{}).WithRequest(ctx)
var messages []models.Message
result, err := qb.CursorPaginate(&messages, options)
```

URL: `GET /messages?cursor=eyJpZCI6MTIzfQ==&limit=50`

### Admin Dashboard with Search
```go
// Admin users list with search and auto pagination
qb := querybuilder.For(&models.User{}).
    WithRequest(ctx).
    AllowedFilters(querybuilder.Partial("name"), querybuilder.Partial("email")).
    AllowedSorts("name", "email", "created_at").
    DefaultSort("-created_at")

var users []models.User
result, err := qb.AutoPaginate(&users)
```

URL: `GET /admin/users?filter[name]=john&pagination_type=simple&limit=50` 