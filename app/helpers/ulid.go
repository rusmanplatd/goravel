package helpers

import (
	"crypto/rand"
	"time"

	"github.com/oklog/ulid/v2"
)

// GenerateULID generates a new ULID
func GenerateULID() string {
	t := time.Now()
	entropy := ulid.Monotonic(rand.Reader, 0)
	id := ulid.MustNew(ulid.Timestamp(t), entropy)
	return id.String()
}

// ParseULID parses a ULID string and returns the time
func ParseULID(ulidStr string) (time.Time, error) {
	id, err := ulid.Parse(ulidStr)
	if err != nil {
		return time.Time{}, err
	}
	return ulid.Time(id.Time()), nil
}

// IsValidULID checks if a string is a valid ULID
func IsValidULID(ulidStr string) bool {
	_, err := ulid.Parse(ulidStr)
	return err == nil
}
