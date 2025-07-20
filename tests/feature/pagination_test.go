package feature

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"goravel/app/helpers"
	"goravel/app/models"
)

func TestCursorBasedPagination(t *testing.T) {
	// Test cursor encoding/decoding
	t.Run("Cursor Encoding and Decoding", func(t *testing.T) {
		cursor := helpers.Cursor{
			ID:        "01HXYZ123456789ABCDEFGHIJK",
			CreatedAt: time.Now(),
		}

		encoded := helpers.EncodeCursor(cursor)
		assert.NotEmpty(t, encoded)

		decoded, err := helpers.DecodeCursor(encoded)
		assert.NoError(t, err)
		assert.NotNil(t, decoded)
		assert.Equal(t, cursor.ID, decoded.ID)
		assert.Equal(t, cursor.CreatedAt.Unix(), decoded.CreatedAt.Unix())
	})

	t.Run("Invalid Cursor Decoding", func(t *testing.T) {
		_, err := helpers.DecodeCursor("invalid-base64")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid cursor format")
	})

	t.Run("Empty Cursor", func(t *testing.T) {
		decoded, err := helpers.DecodeCursor("")
		assert.NoError(t, err)
		assert.Nil(t, decoded)
	})
}

func TestPaginationInfoBuilding(t *testing.T) {
	t.Run("Build Pagination Info", func(t *testing.T) {
		// Mock results with 5 items using actual model structs
		now := time.Now()
		results := []models.Country{
			{
				BaseModel: models.BaseModel{
					ID:        "01HXYZ123456789ABCDEFGHIJK",
					CreatedAt: now,
				},
			},
			{
				BaseModel: models.BaseModel{
					ID:        "01HXYZ123456789ABCDEFGHIJL",
					CreatedAt: now.Add(time.Second),
				},
			},
			{
				BaseModel: models.BaseModel{
					ID:        "01HXYZ123456789ABCDEFGHIJM",
					CreatedAt: now.Add(2 * time.Second),
				},
			},
			{
				BaseModel: models.BaseModel{
					ID:        "01HXYZ123456789ABCDEFGHIJN",
					CreatedAt: now.Add(3 * time.Second),
				},
			},
			{
				BaseModel: models.BaseModel{
					ID:        "01HXYZ123456789ABCDEFGHIJO",
					CreatedAt: now.Add(4 * time.Second),
				},
			},
		}

		limit := 3
		cursor := ""
		hasMore := true

		paginationInfo := helpers.BuildPaginationInfo(results, limit, cursor, hasMore)

		assert.Equal(t, true, paginationInfo["has_more"])
		assert.Equal(t, false, paginationInfo["has_prev"])
		assert.Equal(t, 3, paginationInfo["count"])
		assert.Equal(t, 3, paginationInfo["limit"])
		assert.NotEmpty(t, paginationInfo["next_cursor"])
	})
}
