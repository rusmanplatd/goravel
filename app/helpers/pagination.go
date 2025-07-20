package helpers

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"time"

	"github.com/goravel/framework/contracts/database/orm"
)

// Cursor represents a pagination cursor
type Cursor struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
}

// EncodeCursor encodes a cursor to a base64 string
func EncodeCursor(cursor Cursor) string {
	data, _ := json.Marshal(cursor)
	return base64.StdEncoding.EncodeToString(data)
}

// DecodeCursor decodes a base64 string to a cursor
func DecodeCursor(cursorStr string) (*Cursor, error) {
	if cursorStr == "" {
		return nil, nil
	}

	data, err := base64.StdEncoding.DecodeString(cursorStr)
	if err != nil {
		return nil, fmt.Errorf("invalid cursor format: %v", err)
	}

	var cursor Cursor
	err = json.Unmarshal(data, &cursor)
	if err != nil {
		return nil, fmt.Errorf("invalid cursor data: %v", err)
	}

	return &cursor, nil
}

// ApplyCursorPagination applies cursor-based pagination to a query
func ApplyCursorPagination(query orm.Query, cursorStr string, limit int, reverse bool) (orm.Query, error) {
	if limit <= 0 {
		limit = 10
	}
	if limit > 100 {
		limit = 100
	}

	// Add limit + 1 to check if there are more results
	query = query.Limit(limit + 1)

	if cursorStr != "" {
		cursor, err := DecodeCursor(cursorStr)
		if err != nil {
			return query, err
		}

		if cursor != nil {
			if reverse {
				// For reverse pagination (previous page)
				query = query.Where("(created_at, id) > (?, ?)", cursor.CreatedAt, cursor.ID)
			} else {
				// For forward pagination (next page)
				query = query.Where("(created_at, id) < (?, ?)", cursor.CreatedAt, cursor.ID)
			}
		}
	}

	// Order by created_at DESC, id DESC for consistent ordering
	if reverse {
		query = query.Order("created_at ASC, id ASC")
	} else {
		query = query.Order("created_at DESC, id DESC")
	}

	return query, nil
}

// BuildPaginationInfo builds pagination info for cursor-based pagination
func BuildPaginationInfo(results interface{}, limit int, cursorStr string, hasMore bool) map[string]interface{} {
	// Get the count of results (excluding the extra one we fetched)
	resultCount := getResultCount(results)
	actualCount := resultCount
	if hasMore && resultCount > limit {
		actualCount = limit
	}

	// Build pagination info
	pagination := map[string]interface{}{
		"has_more": hasMore && resultCount > limit,
		"has_prev": cursorStr != "",
		"count":    actualCount,
		"limit":    limit,
	}

	// Add next cursor if there are more results
	if hasMore && resultCount > limit {
		lastItem := getLastItem(results)
		if lastItem != nil {
			nextCursor := Cursor{
				ID:        getItemID(lastItem),
				CreatedAt: getItemCreatedAt(lastItem),
			}
			pagination["next_cursor"] = EncodeCursor(nextCursor)
		}
	}

	// Add previous cursor if we have a current cursor
	if cursorStr != "" {
		pagination["prev_cursor"] = cursorStr
	}

	return pagination
}

// getResultCount gets the count of results using reflection
func getResultCount(results interface{}) int {
	switch v := results.(type) {
	case []interface{}:
		return len(v)
	default:
		// Use reflection to get slice length
		val := reflect.ValueOf(results)
		if val.Kind() == reflect.Slice {
			return val.Len()
		}
		return 0
	}
}

// getLastItem gets the last item from results
func getLastItem(results interface{}) interface{} {
	val := reflect.ValueOf(results)
	if val.Kind() == reflect.Slice && val.Len() > 0 {
		return val.Index(val.Len() - 1).Interface()
	}
	return nil
}

// getItemID gets the ID from an item
func getItemID(item interface{}) string {
	val := reflect.ValueOf(item)
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}

	// Try to get ID field
	idField := val.FieldByName("ID")
	if idField.IsValid() {
		return idField.String()
	}

	// Try to call GetID method
	getIDMethod := val.MethodByName("GetID")
	if getIDMethod.IsValid() {
		results := getIDMethod.Call(nil)
		if len(results) > 0 {
			return results[0].String()
		}
	}

	return ""
}

// getItemCreatedAt gets the CreatedAt from an item
func getItemCreatedAt(item interface{}) time.Time {
	val := reflect.ValueOf(item)
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}

	// Try to get CreatedAt field
	createdAtField := val.FieldByName("CreatedAt")
	if createdAtField.IsValid() {
		if createdAt, ok := createdAtField.Interface().(time.Time); ok {
			return createdAt
		}
	}

	return time.Time{}
}
