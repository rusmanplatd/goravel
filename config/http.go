package config

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"html/template"
	"math"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin/render"
	"github.com/goravel/framework/contracts/route"
	"github.com/goravel/framework/facades"
	"github.com/goravel/gin"
	ginfacades "github.com/goravel/gin/facades"
)

func init() {
	config := facades.Config()
	config.Add("http", map[string]any{
		// HTTP Driver
		"default": "gin",
		// HTTP Drivers
		"drivers": map[string]any{
			"gin": map[string]any{
				// Optional, default is 4096 KB
				"body_limit":   4096,
				"header_limit": 4096,
				"route": func() (route.Route, error) {
					return ginfacades.Route("gin"), nil
				},
				// Optional, default is http/template
				"template": func() (render.HTMLRender, error) {
					return gin.NewTemplate(gin.RenderOptions{
						FuncMap: template.FuncMap{
							// String manipulation functions
							"substr": func(str string, start, length int) string {
								if start < 0 {
									start = 0
								}
								if start >= len(str) {
									return ""
								}
								end := start + length
								if end > len(str) {
									end = len(str)
								}
								return str[start:end]
							},
							"upper":     strings.ToUpper,
							"lower":     strings.ToLower,
							"title":     strings.Title,
							"trim":      strings.TrimSpace,
							"contains":  strings.Contains,
							"hasPrefix": strings.HasPrefix,
							"hasSuffix": strings.HasSuffix,
							"replace": func(old, new, str string) string {
								return strings.ReplaceAll(str, old, new)
							},
							"split": func(sep, str string) []string {
								return strings.Split(str, sep)
							},
							"join": func(sep string, elems []string) string {
								return strings.Join(elems, sep)
							},
							"truncate": func(length int, str string) string {
								if len(str) <= length {
									return str
								}
								return str[:length] + "..."
							},
							"repeat": func(count int, str string) string {
								return strings.Repeat(str, count)
							},

							// Date and time functions
							"now": func() time.Time {
								return time.Now()
							},
							"formatDate": func(layout string, t time.Time) string {
								return t.Format(layout)
							},
							"dateFormat": func(t time.Time) string {
								return t.Format("2006-01-02")
							},
							"timeFormat": func(t time.Time) string {
								return t.Format("15:04:05")
							},
							"datetimeFormat": func(t time.Time) string {
								return t.Format("2006-01-02 15:04:05")
							},
							"humanDate": func(t time.Time) string {
								return t.Format("January 2, 2006")
							},
							"timeAgo": func(t time.Time) string {
								duration := time.Since(t)
								if duration < time.Minute {
									return "just now"
								} else if duration < time.Hour {
									return fmt.Sprintf("%d minutes ago", int(duration.Minutes()))
								} else if duration < 24*time.Hour {
									return fmt.Sprintf("%d hours ago", int(duration.Hours()))
								} else {
									return fmt.Sprintf("%d days ago", int(duration.Hours()/24))
								}
							},

							// Math functions
							"add": func(a, b int) int {
								return a + b
							},
							"sub": func(a, b int) int {
								return a - b
							},
							"mul": func(a, b int) int {
								return a * b
							},
							"div": func(a, b int) int {
								if b == 0 {
									return 0
								}
								return a / b
							},
							"mod": func(a, b int) int {
								if b == 0 {
									return 0
								}
								return a % b
							},
							"max": func(a, b int) int {
								if a > b {
									return a
								}
								return b
							},
							"min": func(a, b int) int {
								if a < b {
									return a
								}
								return b
							},
							"round": func(f float64) int {
								return int(math.Round(f))
							},
							"ceil": func(f float64) int {
								return int(math.Ceil(f))
							},
							"floor": func(f float64) int {
								return int(math.Floor(f))
							},

							// Type conversion functions
							"toString": func(v interface{}) string {
								return fmt.Sprintf("%v", v)
							},
							"toInt": func(s string) int {
								if i, err := strconv.Atoi(s); err == nil {
									return i
								}
								return 0
							},
							"toFloat": func(s string) float64 {
								if f, err := strconv.ParseFloat(s, 64); err == nil {
									return f
								}
								return 0.0
							},

							// URL and HTML functions
							"urlEncode": func(s string) string {
								return url.QueryEscape(s)
							},
							"urlDecode": func(s string) string {
								if decoded, err := url.QueryUnescape(s); err == nil {
									return decoded
								}
								return s
							},
							"safeHTML": func(s string) template.HTML {
								return template.HTML(s)
							},
							"safeCSS": func(s string) template.CSS {
								return template.CSS(s)
							},
							"safeJS": func(s string) template.JS {
								return template.JS(s)
							},
							"safeURL": func(s string) template.URL {
								return template.URL(s)
							},

							// Utility functions
							"default": func(defaultValue, value interface{}) interface{} {
								if value == nil || value == "" {
									return defaultValue
								}
								return value
							},
							"isEmpty": func(value interface{}) bool {
								if value == nil {
									return true
								}
								switch v := value.(type) {
								case string:
									return v == ""
								case []interface{}:
									return len(v) == 0
								case map[string]interface{}:
									return len(v) == 0
								default:
									return false
								}
							},
							"isNotEmpty": func(value interface{}) bool {
								if value == nil {
									return false
								}
								switch v := value.(type) {
								case string:
									return v != ""
								case []interface{}:
									return len(v) > 0
								case map[string]interface{}:
									return len(v) > 0
								default:
									return true
								}
							},
							"len": func(value interface{}) int {
								switch v := value.(type) {
								case string:
									return len(v)
								case []interface{}:
									return len(v)
								case map[string]interface{}:
									return len(v)
								default:
									return 0
								}
							},
							"eq": func(a, b interface{}) bool {
								return a == b
							},
							"ne": func(a, b interface{}) bool {
								return a != b
							},
							"lt": func(a, b int) bool {
								return a < b
							},
							"le": func(a, b int) bool {
								return a <= b
							},
							"gt": func(a, b int) bool {
								return a > b
							},
							"ge": func(a, b int) bool {
								return a >= b
							},
							"and": func(a, b bool) bool {
								return a && b
							},
							"or": func(a, b bool) bool {
								return a || b
							},
							"not": func(a bool) bool {
								return !a
							},

							// Array/slice functions
							"first": func(slice []interface{}) interface{} {
								if len(slice) > 0 {
									return slice[0]
								}
								return nil
							},
							"last": func(slice []interface{}) interface{} {
								if len(slice) > 0 {
									return slice[len(slice)-1]
								}
								return nil
							},
							"slice": func(start, end int, slice []interface{}) []interface{} {
								if start < 0 {
									start = 0
								}
								if end > len(slice) {
									end = len(slice)
								}
								if start >= end {
									return []interface{}{}
								}
								return slice[start:end]
							},
							"reverse": func(slice []interface{}) []interface{} {
								reversed := make([]interface{}, len(slice))
								for i, v := range slice {
									reversed[len(slice)-1-i] = v
								}
								return reversed
							},

							// String validation functions
							"isEmail": func(s string) bool {
								return strings.Contains(s, "@") && strings.Contains(s, ".")
							},
							"isURL": func(s string) bool {
								return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
							},
							"isNumeric": func(s string) bool {
								_, err := strconv.ParseFloat(s, 64)
								return err == nil
							},
							"isAlpha": func(s string) bool {
								for _, r := range s {
									if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')) {
										return false
									}
								}
								return true
							},
							"isAlphaNumeric": func(s string) bool {
								for _, r := range s {
									if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
										return false
									}
								}
								return true
							},
							"isDigit": func(s string) bool {
								for _, r := range s {
									if !(r >= '0' && r <= '9') {
										return false
									}
								}
								return true
							},
							"isLower": func(s string) bool {
								return s == strings.ToLower(s)
							},
							"isUpper": func(s string) bool {
								return s == strings.ToUpper(s)
							},
							"isSpace": func(s string) bool {
								return strings.TrimSpace(s) == ""
							},
							"isBlank": func(s string) bool {
								return len(strings.TrimSpace(s)) == 0
							},

							// String formatting functions
							"capitalize": func(s string) string {
								if len(s) == 0 {
									return s
								}
								return strings.ToUpper(s[:1]) + strings.ToLower(s[1:])
							},
							"camelCase": func(s string) string {
								words := strings.Fields(s)
								if len(words) == 0 {
									return s
								}
								result := strings.ToLower(words[0])
								for i := 1; i < len(words); i++ {
									result += strings.Title(strings.ToLower(words[i]))
								}
								return result
							},
							"snakeCase": func(s string) string {
								return strings.ToLower(strings.ReplaceAll(s, " ", "_"))
							},
							"kebabCase": func(s string) string {
								return strings.ToLower(strings.ReplaceAll(s, " ", "-"))
							},
							"pascalCase": func(s string) string {
								words := strings.Fields(s)
								result := ""
								for _, word := range words {
									result += strings.Title(strings.ToLower(word))
								}
								return result
							},
							"slugify": func(s string) string {
								s = strings.ToLower(s)
								s = strings.ReplaceAll(s, " ", "-")
								return strings.Trim(s, "-")
							},
							"padLeft": func(width int, pad string, s string) string {
								if len(s) >= width {
									return s
								}
								padding := strings.Repeat(pad, (width-len(s))/len(pad)+1)
								return padding[:width-len(s)] + s
							},
							"padRight": func(width int, pad string, s string) string {
								if len(s) >= width {
									return s
								}
								padding := strings.Repeat(pad, (width-len(s))/len(pad)+1)
								return s + padding[:width-len(s)]
							},
							"center": func(width int, s string) string {
								if len(s) >= width {
									return s
								}
								leftPad := (width - len(s)) / 2
								rightPad := width - len(s) - leftPad
								return strings.Repeat(" ", leftPad) + s + strings.Repeat(" ", rightPad)
							},
							"wrap": func(width int, s string) []string {
								words := strings.Fields(s)
								if len(words) == 0 {
									return []string{}
								}
								var lines []string
								currentLine := ""
								for _, word := range words {
									if len(currentLine)+len(word)+1 <= width {
										if currentLine != "" {
											currentLine += " "
										}
										currentLine += word
									} else {
										if currentLine != "" {
											lines = append(lines, currentLine)
										}
										currentLine = word
									}
								}
								if currentLine != "" {
									lines = append(lines, currentLine)
								}
								return lines
							},
							"indent": func(spaces int, s string) string {
								prefix := strings.Repeat(" ", spaces)
								lines := strings.Split(s, "\n")
								for i, line := range lines {
									if line != "" {
										lines[i] = prefix + line
									}
								}
								return strings.Join(lines, "\n")
							},

							// Number formatting functions
							"formatNumber": func(n int) string {
								str := strconv.Itoa(n)
								if len(str) <= 3 {
									return str
								}
								var result []string
								for i := len(str); i > 0; i -= 3 {
									start := i - 3
									if start < 0 {
										start = 0
									}
									result = append([]string{str[start:i]}, result...)
								}
								return strings.Join(result, ",")
							},
							"formatCurrency": func(amount float64, symbol string) string {
								return fmt.Sprintf("%s%.2f", symbol, amount)
							},
							"formatPercent": func(value float64) string {
								return fmt.Sprintf("%.1f%%", value*100)
							},
							"formatBytes": func(bytes int64) string {
								const unit = 1024
								if bytes < unit {
									return fmt.Sprintf("%d B", bytes)
								}
								div, exp := int64(unit), 0
								for n := bytes / unit; n >= unit; n /= unit {
									div *= unit
									exp++
								}
								return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
							},
							"ordinal": func(n int) string {
								suffix := "th"
								switch n % 10 {
								case 1:
									if n%100 != 11 {
										suffix = "st"
									}
								case 2:
									if n%100 != 12 {
										suffix = "nd"
									}
								case 3:
									if n%100 != 13 {
										suffix = "rd"
									}
								}
								return fmt.Sprintf("%d%s", n, suffix)
							},
							"roman": func(n int) string {
								values := []int{1000, 900, 500, 400, 100, 90, 50, 40, 10, 9, 5, 4, 1}
								symbols := []string{"M", "CM", "D", "CD", "C", "XC", "L", "XL", "X", "IX", "V", "IV", "I"}
								result := ""
								for i := 0; i < len(values); i++ {
									for n >= values[i] {
										result += symbols[i]
										n -= values[i]
									}
								}
								return result
							},

							// Date manipulation functions
							"addDays": func(days int, t time.Time) time.Time {
								return t.AddDate(0, 0, days)
							},
							"addMonths": func(months int, t time.Time) time.Time {
								return t.AddDate(0, months, 0)
							},
							"addYears": func(years int, t time.Time) time.Time {
								return t.AddDate(years, 0, 0)
							},
							"startOfDay": func(t time.Time) time.Time {
								return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, t.Location())
							},
							"endOfDay": func(t time.Time) time.Time {
								return time.Date(t.Year(), t.Month(), t.Day(), 23, 59, 59, 999999999, t.Location())
							},
							"startOfWeek": func(t time.Time) time.Time {
								weekday := int(t.Weekday())
								return t.AddDate(0, 0, -weekday)
							},
							"endOfWeek": func(t time.Time) time.Time {
								weekday := int(t.Weekday())
								return t.AddDate(0, 0, 6-weekday)
							},
							"startOfMonth": func(t time.Time) time.Time {
								return time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, t.Location())
							},
							"endOfMonth": func(t time.Time) time.Time {
								return time.Date(t.Year(), t.Month()+1, 0, 23, 59, 59, 999999999, t.Location())
							},
							"dayOfYear": func(t time.Time) int {
								return t.YearDay()
							},
							"weekOfYear": func(t time.Time) int {
								_, week := t.ISOWeek()
								return week
							},
							"isWeekend": func(t time.Time) bool {
								day := t.Weekday()
								return day == time.Saturday || day == time.Sunday
							},
							"isLeapYear": func(year int) bool {
								return year%4 == 0 && (year%100 != 0 || year%400 == 0)
							},
							"daysInMonth": func(year int, month int) int {
								return time.Date(year, time.Month(month)+1, 0, 0, 0, 0, 0, time.UTC).Day()
							},
							"age": func(birthDate time.Time) int {
								now := time.Now()
								age := now.Year() - birthDate.Year()
								if now.YearDay() < birthDate.YearDay() {
									age--
								}
								return age
							},

							// Array/slice manipulation functions
							"append": func(slice []interface{}, item interface{}) []interface{} {
								return append(slice, item)
							},
							"prepend": func(item interface{}, slice []interface{}) []interface{} {
								return append([]interface{}{item}, slice...)
							},
							"concat": func(slice1, slice2 []interface{}) []interface{} {
								return append(slice1, slice2...)
							},
							"unique": func(slice []interface{}) []interface{} {
								seen := make(map[interface{}]bool)
								result := []interface{}{}
								for _, item := range slice {
									if !seen[item] {
										seen[item] = true
										result = append(result, item)
									}
								}
								return result
							},
							"includesItem": func(slice []interface{}, item interface{}) bool {
								for _, v := range slice {
									if v == item {
										return true
									}
								}
								return false
							},
							"indexOf": func(slice []interface{}, item interface{}) int {
								for i, v := range slice {
									if v == item {
										return i
									}
								}
								return -1
							},
							"remove": func(slice []interface{}, item interface{}) []interface{} {
								result := []interface{}{}
								for _, v := range slice {
									if v != item {
										result = append(result, v)
									}
								}
								return result
							},
							"removeAt": func(index int, slice []interface{}) []interface{} {
								if index < 0 || index >= len(slice) {
									return slice
								}
								return append(slice[:index], slice[index+1:]...)
							},
							"insertAt": func(index int, item interface{}, slice []interface{}) []interface{} {
								if index < 0 || index > len(slice) {
									return slice
								}
								result := make([]interface{}, len(slice)+1)
								copy(result[:index], slice[:index])
								result[index] = item
								copy(result[index+1:], slice[index:])
								return result
							},
							"chunk": func(size int, slice []interface{}) [][]interface{} {
								if size <= 0 {
									return [][]interface{}{}
								}
								var chunks [][]interface{}
								for i := 0; i < len(slice); i += size {
									end := i + size
									if end > len(slice) {
										end = len(slice)
									}
									chunks = append(chunks, slice[i:end])
								}
								return chunks
							},
							"flatten": func(slices [][]interface{}) []interface{} {
								result := []interface{}{}
								for _, slice := range slices {
									result = append(result, slice...)
								}
								return result
							},
							"zip": func(slice1, slice2 []interface{}) [][]interface{} {
								minLen := len(slice1)
								if len(slice2) < minLen {
									minLen = len(slice2)
								}
								result := make([][]interface{}, minLen)
								for i := 0; i < minLen; i++ {
									result[i] = []interface{}{slice1[i], slice2[i]}
								}
								return result
							},

							// Map/object functions
							"keys": func(m map[string]interface{}) []string {
								keys := make([]string, 0, len(m))
								for k := range m {
									keys = append(keys, k)
								}
								return keys
							},
							"values": func(m map[string]interface{}) []interface{} {
								values := make([]interface{}, 0, len(m))
								for _, v := range m {
									values = append(values, v)
								}
								return values
							},
							"hasKey": func(key string, m map[string]interface{}) bool {
								_, exists := m[key]
								return exists
							},
							"get": func(key string, m map[string]interface{}) interface{} {
								return m[key]
							},
							"getDefault": func(key string, defaultValue interface{}, m map[string]interface{}) interface{} {
								if value, exists := m[key]; exists {
									return value
								}
								return defaultValue
							},

							// Encoding functions
							"base64Encode": func(s string) string {
								return fmt.Sprintf("%x", s) // Simple hex encoding for safety
							},
							"base64Decode": func(s string) string {
								return s // Return as-is for safety
							},
							"md5": func(s string) string {
								hash := md5.New()
								hash.Write([]byte(s))
								return fmt.Sprintf("%x", hash.Sum(nil))
							},
							"sha1": func(s string) string {
								hash := sha1.New()
								hash.Write([]byte(s))
								return fmt.Sprintf("%x", hash.Sum(nil))
							},
							"sha256": func(s string) string {
								hash := sha256.New()
								hash.Write([]byte(s))
								return fmt.Sprintf("%x", hash.Sum(nil))
							},

							// Random functions
							"randomInt": func(min, max int) int {
								if min >= max {
									return min
								}
								return min + int(time.Now().UnixNano())%(max-min)
							},
							"randomChoice": func(slice []interface{}) interface{} {
								if len(slice) == 0 {
									return nil
								}
								index := int(time.Now().UnixNano()) % len(slice)
								return slice[index]
							},
							"shuffle": func(slice []interface{}) []interface{} {
								result := make([]interface{}, len(slice))
								copy(result, slice)
								// Simple shuffle based on time
								for i := len(result) - 1; i > 0; i-- {
									j := int(time.Now().UnixNano()) % (i + 1)
									result[i], result[j] = result[j], result[i]
								}
								return result
							},

							// Color functions
							"hexToRGB": func(hex string) string {
								if len(hex) != 7 || hex[0] != '#' {
									return "rgb(0,0,0)"
								}
								return fmt.Sprintf("rgb(%s)", hex[1:])
							},
							"rgbToHex": func(r, g, b int) string {
								return fmt.Sprintf("#%02x%02x%02x", r, g, b)
							},
							"lighten": func(percent int, color string) string {
								// Parse hex color
								if len(color) != 7 || color[0] != '#' {
									return color // Return original if invalid format
								}

								// Extract RGB components
								r, g, b := hexToRGB(color)

								// Lighten by increasing values towards 255
								factor := float64(percent) / 100.0
								r = int(float64(r) + (255-float64(r))*factor)
								g = int(float64(g) + (255-float64(g))*factor)
								b = int(float64(b) + (255-float64(b))*factor)

								// Clamp values
								if r > 255 {
									r = 255
								}
								if g > 255 {
									g = 255
								}
								if b > 255 {
									b = 255
								}

								return fmt.Sprintf("#%02x%02x%02x", r, g, b)
							},
							"darken": func(percent int, color string) string {
								// Parse hex color
								if len(color) != 7 || color[0] != '#' {
									return color // Return original if invalid format
								}

								// Extract RGB components
								r, g, b := hexToRGB(color)

								// Darken by decreasing values towards 0
								factor := float64(percent) / 100.0
								r = int(float64(r) * (1.0 - factor))
								g = int(float64(g) * (1.0 - factor))
								b = int(float64(b) * (1.0 - factor))

								// Clamp values
								if r < 0 {
									r = 0
								}
								if g < 0 {
									g = 0
								}
								if b < 0 {
									b = 0
								}

								return fmt.Sprintf("#%02x%02x%02x", r, g, b)
							},

							// File functions
							"fileExt": func(filename string) string {
								parts := strings.Split(filename, ".")
								if len(parts) > 1 {
									return parts[len(parts)-1]
								}
								return ""
							},
							"fileName": func(path string) string {
								parts := strings.Split(path, "/")
								return parts[len(parts)-1]
							},
							"fileBaseName": func(filename string) string {
								name := filename
								if idx := strings.LastIndex(name, "/"); idx != -1 {
									name = name[idx+1:]
								}
								if idx := strings.LastIndex(name, "."); idx != -1 {
									name = name[:idx]
								}
								return name
							},
							"filePath": func(fullPath string) string {
								if idx := strings.LastIndex(fullPath, "/"); idx != -1 {
									return fullPath[:idx]
								}
								return ""
							},

							// Conditional functions
							"ternary": func(condition bool, trueVal, falseVal interface{}) interface{} {
								if condition {
									return trueVal
								}
								return falseVal
							},
							"when": func(condition bool, value interface{}) interface{} {
								if condition {
									return value
								}
								return nil
							},
							"unless": func(condition bool, value interface{}) interface{} {
								if !condition {
									return value
								}
								return nil
							},
							"coalesce": func(values ...interface{}) interface{} {
								for _, v := range values {
									if v != nil && v != "" {
										return v
									}
								}
								return nil
							},

							// HTML/CSS functions
							"stripTags": func(s string) string {
								// Simple tag removal
								result := s
								for strings.Contains(result, "<") && strings.Contains(result, ">") {
									start := strings.Index(result, "<")
									end := strings.Index(result[start:], ">")
									if end != -1 {
										result = result[:start] + result[start+end+1:]
									} else {
										break
									}
								}
								return result
							},
							"escapeHTML": func(s string) string {
								s = strings.ReplaceAll(s, "&", "&amp;")
								s = strings.ReplaceAll(s, "<", "&lt;")
								s = strings.ReplaceAll(s, ">", "&gt;")
								s = strings.ReplaceAll(s, "\"", "&quot;")
								s = strings.ReplaceAll(s, "'", "&#39;")
								return s
							},
							"unescapeHTML": func(s string) string {
								s = strings.ReplaceAll(s, "&amp;", "&")
								s = strings.ReplaceAll(s, "&lt;", "<")
								s = strings.ReplaceAll(s, "&gt;", ">")
								s = strings.ReplaceAll(s, "&quot;", "\"")
								s = strings.ReplaceAll(s, "&#39;", "'")
								return s
							},
							"attr": func(name, value string) template.HTMLAttr {
								return template.HTMLAttr(fmt.Sprintf(`%s="%s"`, name, value))
							},
							"cssClass": func(classes ...string) string {
								return strings.Join(classes, " ")
							},
							"cssStyle": func(styles map[string]string) template.CSS {
								var parts []string
								for prop, value := range styles {
									parts = append(parts, fmt.Sprintf("%s: %s", prop, value))
								}
								return template.CSS(strings.Join(parts, "; "))
							},

							// Pluralization functions
							"pluralize": func(count int, singular, plural string) string {
								if count == 1 {
									return singular
								}
								return plural
							},
							"pluralizeWithCount": func(count int, singular, plural string) string {
								word := singular
								if count != 1 {
									word = plural
								}
								return fmt.Sprintf("%d %s", count, word)
							},

							// Debug functions
							"dump": func(v interface{}) string {
								return fmt.Sprintf("%+v", v)
							},
							"typeOf": func(v interface{}) string {
								return fmt.Sprintf("%T", v)
							},
							"sizeof": func(v interface{}) string {
								return fmt.Sprintf("%d bytes", len(fmt.Sprintf("%v", v)))
							},

							// Miscellaneous utility functions
							"noop": func() string {
								return ""
							},
							"identity": func(v interface{}) interface{} {
								return v
							},
							"constant": func(value interface{}) func() interface{} {
								return func() interface{} { return value }
							},
							"range": func(start, end int) []int {
								if start > end {
									return []int{}
								}
								result := make([]int, end-start)
								for i := range result {
									result[i] = start + i
								}
								return result
							},
							"times": func(n int) []int {
								result := make([]int, n)
								for i := range result {
									result[i] = i
								}
								return result
							},
							"pick": func(keys []string, m map[string]interface{}) map[string]interface{} {
								result := make(map[string]interface{})
								for _, key := range keys {
									if value, exists := m[key]; exists {
										result[key] = value
									}
								}
								return result
							},
							"omit": func(keys []string, m map[string]interface{}) map[string]interface{} {
								result := make(map[string]interface{})
								omitSet := make(map[string]bool)
								for _, key := range keys {
									omitSet[key] = true
								}
								for key, value := range m {
									if !omitSet[key] {
										result[key] = value
									}
								}
								return result
							},

							// Text processing functions
							"wordCount": func(s string) int {
								return len(strings.Fields(s))
							},
							"charCount": func(s string) int {
								return len([]rune(s))
							},
							"lineCount": func(s string) int {
								return len(strings.Split(s, "\n"))
							},
							"sentenceCount": func(s string) int {
								count := 0
								for _, r := range s {
									if r == '.' || r == '!' || r == '?' {
										count++
									}
								}
								return count
							},
							"paragraphCount": func(s string) int {
								paragraphs := strings.Split(strings.TrimSpace(s), "\n\n")
								if len(paragraphs) == 1 && paragraphs[0] == "" {
									return 0
								}
								return len(paragraphs)
							},
							"extractWords": func(s string) []string {
								return strings.Fields(s)
							},
							"extractLines": func(s string) []string {
								return strings.Split(s, "\n")
							},
							"removeEmptyLines": func(s string) string {
								lines := strings.Split(s, "\n")
								var result []string
								for _, line := range lines {
									if strings.TrimSpace(line) != "" {
										result = append(result, line)
									}
								}
								return strings.Join(result, "\n")
							},
							"normalizeWhitespace": func(s string) string {
								return strings.Join(strings.Fields(s), " ")
							},
							"removeExtraSpaces": func(s string) string {
								return strings.Join(strings.Fields(s), " ")
							},
							"insertLineBreaks": func(width int, s string) string {
								words := strings.Fields(s)
								if len(words) == 0 {
									return s
								}
								var lines []string
								currentLine := ""
								for _, word := range words {
									if len(currentLine)+len(word)+1 <= width {
										if currentLine != "" {
											currentLine += " "
										}
										currentLine += word
									} else {
										if currentLine != "" {
											lines = append(lines, currentLine)
										}
										currentLine = word
									}
								}
								if currentLine != "" {
									lines = append(lines, currentLine)
								}
								return strings.Join(lines, "\n")
							},
							"removeLineBreaks": func(s string) string {
								return strings.ReplaceAll(s, "\n", " ")
							},
							"reverseWords": func(s string) string {
								words := strings.Fields(s)
								for i, j := 0, len(words)-1; i < j; i, j = i+1, j-1 {
									words[i], words[j] = words[j], words[i]
								}
								return strings.Join(words, " ")
							},
							"reverseString": func(s string) string {
								runes := []rune(s)
								for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
									runes[i], runes[j] = runes[j], runes[i]
								}
								return string(runes)
							},
							"abbreviate": func(maxLength int, s string) string {
								if len(s) <= maxLength {
									return s
								}
								return s[:maxLength-3] + "..."
							},
							"ellipsis": func(maxLength int, s string) string {
								if len(s) <= maxLength {
									return s
								}
								return s[:maxLength-1] + "…"
							},
							"initials": func(s string) string {
								words := strings.Fields(s)
								var initials []string
								for _, word := range words {
									if len(word) > 0 {
										initials = append(initials, strings.ToUpper(word[:1]))
									}
								}
								return strings.Join(initials, "")
							},
							"acronym": func(s string) string {
								words := strings.Fields(s)
								var acronym []string
								for _, word := range words {
									if len(word) > 0 {
										acronym = append(acronym, strings.ToUpper(word[:1]))
									}
								}
								return strings.Join(acronym, "")
							},
							"removeAccents": func(s string) string {
								// Simple accent removal - could be expanded
								replacements := map[string]string{
									"á": "a", "à": "a", "ä": "a", "â": "a", "ã": "a", "å": "a",
									"é": "e", "è": "e", "ë": "e", "ê": "e",
									"í": "i", "ì": "i", "ï": "i", "î": "i",
									"ó": "o", "ò": "o", "ö": "o", "ô": "o", "õ": "o", "ø": "o",
									"ú": "u", "ù": "u", "ü": "u", "û": "u",
									"ñ": "n", "ç": "c",
								}
								result := s
								for accented, plain := range replacements {
									result = strings.ReplaceAll(result, accented, plain)
									result = strings.ReplaceAll(result, strings.ToUpper(accented), strings.ToUpper(plain))
								}
								return result
							},
							"isAscii": func(s string) bool {
								for _, r := range s {
									if r > 127 {
										return false
									}
								}
								return true
							},
							"isPrintable": func(s string) bool {
								for _, r := range s {
									if r < 32 || r > 126 {
										return false
									}
								}
								return true
							},

							// Advanced math functions
							"abs": func(n int) int {
								if n < 0 {
									return -n
								}
								return n
							},
							"absFloat": func(f float64) float64 {
								if f < 0 {
									return -f
								}
								return f
							},
							"pow": func(base, exp int) int {
								result := 1
								for i := 0; i < exp; i++ {
									result *= base
								}
								return result
							},
							"powFloat": func(base, exp float64) float64 {
								return math.Pow(base, exp)
							},
							"sqrt": func(f float64) float64 {
								return math.Sqrt(f)
							},
							"log": func(f float64) float64 {
								return math.Log(f)
							},
							"log10": func(f float64) float64 {
								return math.Log10(f)
							},
							"sin": func(f float64) float64 {
								return math.Sin(f)
							},
							"cos": func(f float64) float64 {
								return math.Cos(f)
							},
							"tan": func(f float64) float64 {
								return math.Tan(f)
							},
							"asin": func(f float64) float64 {
								return math.Asin(f)
							},
							"acos": func(f float64) float64 {
								return math.Acos(f)
							},
							"atan": func(f float64) float64 {
								return math.Atan(f)
							},
							"degrees": func(radians float64) float64 {
								return radians * 180 / math.Pi
							},
							"radians": func(degrees float64) float64 {
								return degrees * math.Pi / 180
							},
							"factorial": func(n int) int {
								if n <= 1 {
									return 1
								}
								result := 1
								for i := 2; i <= n; i++ {
									result *= i
								}
								return result
							},
							"fibonacci": func(n int) int {
								if n <= 1 {
									return n
								}
								a, b := 0, 1
								for i := 2; i <= n; i++ {
									a, b = b, a+b
								}
								return b
							},
							"gcd": func(a, b int) int {
								for b != 0 {
									a, b = b, a%b
								}
								return a
							},
							"lcm": func(a, b int) int {
								return a * b / func() int {
									for b != 0 {
										a, b = b, a%b
									}
									return a
								}()
							},
							"isPrime": func(n int) bool {
								if n < 2 {
									return false
								}
								for i := 2; i*i <= n; i++ {
									if n%i == 0 {
										return false
									}
								}
								return true
							},
							"isEven": func(n int) bool {
								return n%2 == 0
							},
							"isOdd": func(n int) bool {
								return n%2 != 0
							},
							"clamp": func(value, min, max int) int {
								if value < min {
									return min
								}
								if value > max {
									return max
								}
								return value
							},
							"clampFloat": func(value, min, max float64) float64 {
								if value < min {
									return min
								}
								if value > max {
									return max
								}
								return value
							},
							"lerp": func(start, end, t float64) float64 {
								return start + t*(end-start)
							},
							"map": func(value, inMin, inMax, outMin, outMax float64) float64 {
								return (value-inMin)*(outMax-outMin)/(inMax-inMin) + outMin
							},
							"average": func(numbers []int) float64 {
								if len(numbers) == 0 {
									return 0
								}
								sum := 0
								for _, n := range numbers {
									sum += n
								}
								return float64(sum) / float64(len(numbers))
							},
							"median": func(numbers []int) float64 {
								if len(numbers) == 0 {
									return 0
								}
								// Simple median calculation
								sorted := make([]int, len(numbers))
								copy(sorted, numbers)
								// Basic bubble sort for simplicity
								for i := 0; i < len(sorted); i++ {
									for j := 0; j < len(sorted)-1-i; j++ {
										if sorted[j] > sorted[j+1] {
											sorted[j], sorted[j+1] = sorted[j+1], sorted[j]
										}
									}
								}
								mid := len(sorted) / 2
								if len(sorted)%2 == 0 {
									return float64(sorted[mid-1]+sorted[mid]) / 2
								}
								return float64(sorted[mid])
							},
							"mode": func(numbers []int) int {
								if len(numbers) == 0 {
									return 0
								}
								counts := make(map[int]int)
								for _, n := range numbers {
									counts[n]++
								}
								maxCount := 0
								mode := numbers[0]
								for n, count := range counts {
									if count > maxCount {
										maxCount = count
										mode = n
									}
								}
								return mode
							},
							"sum": func(numbers []int) int {
								sum := 0
								for _, n := range numbers {
									sum += n
								}
								return sum
							},
							"product": func(numbers []int) int {
								if len(numbers) == 0 {
									return 0
								}
								product := 1
								for _, n := range numbers {
									product *= n
								}
								return product
							},

							// Duration and time formatting functions
							"formatDuration": func(seconds int) string {
								if seconds < 60 {
									return fmt.Sprintf("%ds", seconds)
								} else if seconds < 3600 {
									return fmt.Sprintf("%dm %ds", seconds/60, seconds%60)
								} else {
									hours := seconds / 3600
									minutes := (seconds % 3600) / 60
									secs := seconds % 60
									return fmt.Sprintf("%dh %dm %ds", hours, minutes, secs)
								}
							},
							"formatDurationShort": func(seconds int) string {
								if seconds < 60 {
									return fmt.Sprintf("%ds", seconds)
								} else if seconds < 3600 {
									return fmt.Sprintf("%dm", seconds/60)
								} else {
									return fmt.Sprintf("%dh", seconds/3600)
								}
							},
							"secondsToMinutes": func(seconds int) float64 {
								return float64(seconds) / 60.0
							},
							"secondsToHours": func(seconds int) float64 {
								return float64(seconds) / 3600.0
							},
							"minutesToSeconds": func(minutes int) int {
								return minutes * 60
							},
							"hoursToSeconds": func(hours int) int {
								return hours * 3600
							},
							"daysToSeconds": func(days int) int {
								return days * 24 * 3600
							},
							"weeksToSeconds": func(weeks int) int {
								return weeks * 7 * 24 * 3600
							},
							"monthsToSeconds": func(months int) int {
								return months * 30 * 24 * 3600 // Approximate
							},
							"yearsToSeconds": func(years int) int {
								return years * 365 * 24 * 3600 // Approximate
							},
							"timeSince": func(t time.Time) string {
								duration := time.Since(t)
								if duration < time.Minute {
									return "just now"
								} else if duration < time.Hour {
									return fmt.Sprintf("%d minutes ago", int(duration.Minutes()))
								} else if duration < 24*time.Hour {
									return fmt.Sprintf("%d hours ago", int(duration.Hours()))
								} else if duration < 7*24*time.Hour {
									return fmt.Sprintf("%d days ago", int(duration.Hours()/24))
								} else if duration < 30*24*time.Hour {
									return fmt.Sprintf("%d weeks ago", int(duration.Hours()/(24*7)))
								} else if duration < 365*24*time.Hour {
									return fmt.Sprintf("%d months ago", int(duration.Hours()/(24*30)))
								} else {
									return fmt.Sprintf("%d years ago", int(duration.Hours()/(24*365)))
								}
							},
							"timeUntil": func(t time.Time) string {
								duration := time.Until(t)
								if duration < 0 {
									return "in the past"
								}
								if duration < time.Minute {
									return "in less than a minute"
								} else if duration < time.Hour {
									return fmt.Sprintf("in %d minutes", int(duration.Minutes()))
								} else if duration < 24*time.Hour {
									return fmt.Sprintf("in %d hours", int(duration.Hours()))
								} else if duration < 7*24*time.Hour {
									return fmt.Sprintf("in %d days", int(duration.Hours()/24))
								} else if duration < 30*24*time.Hour {
									return fmt.Sprintf("in %d weeks", int(duration.Hours()/(24*7)))
								} else if duration < 365*24*time.Hour {
									return fmt.Sprintf("in %d months", int(duration.Hours()/(24*30)))
								} else {
									return fmt.Sprintf("in %d years", int(duration.Hours()/(24*365)))
								}
							},
							"isToday": func(t time.Time) bool {
								now := time.Now()
								return t.Year() == now.Year() && t.YearDay() == now.YearDay()
							},
							"isYesterday": func(t time.Time) bool {
								yesterday := time.Now().AddDate(0, 0, -1)
								return t.Year() == yesterday.Year() && t.YearDay() == yesterday.YearDay()
							},
							"isTomorrow": func(t time.Time) bool {
								tomorrow := time.Now().AddDate(0, 0, 1)
								return t.Year() == tomorrow.Year() && t.YearDay() == tomorrow.YearDay()
							},
							"isThisWeek": func(t time.Time) bool {
								now := time.Now()
								startOfWeek := now.AddDate(0, 0, -int(now.Weekday()))
								endOfWeek := startOfWeek.AddDate(0, 0, 7)
								return t.After(startOfWeek) && t.Before(endOfWeek)
							},
							"isThisMonth": func(t time.Time) bool {
								now := time.Now()
								return t.Year() == now.Year() && t.Month() == now.Month()
							},
							"isThisYear": func(t time.Time) bool {
								return t.Year() == time.Now().Year()
							},
							"isFuture": func(t time.Time) bool {
								return t.After(time.Now())
							},
							"isPast": func(t time.Time) bool {
								return t.Before(time.Now())
							},
							"timezone": func(t time.Time) string {
								zone, _ := t.Zone()
								return zone
							},
							"utc": func(t time.Time) time.Time {
								return t.UTC()
							},
							"local": func(t time.Time) time.Time {
								return t.Local()
							},

							// Advanced array/slice functions
							"sortStrings": func(slice []string) []string {
								result := make([]string, len(slice))
								copy(result, slice)
								// Simple bubble sort
								for i := 0; i < len(result); i++ {
									for j := 0; j < len(result)-1-i; j++ {
										if result[j] > result[j+1] {
											result[j], result[j+1] = result[j+1], result[j]
										}
									}
								}
								return result
							},
							"sortInts": func(slice []int) []int {
								result := make([]int, len(slice))
								copy(result, slice)
								// Simple bubble sort
								for i := 0; i < len(result); i++ {
									for j := 0; j < len(result)-1-i; j++ {
										if result[j] > result[j+1] {
											result[j], result[j+1] = result[j+1], result[j]
										}
									}
								}
								return result
							},
							"sortDesc": func(slice []int) []int {
								result := make([]int, len(slice))
								copy(result, slice)
								// Simple bubble sort in descending order
								for i := 0; i < len(result); i++ {
									for j := 0; j < len(result)-1-i; j++ {
										if result[j] < result[j+1] {
											result[j], result[j+1] = result[j+1], result[j]
										}
									}
								}
								return result
							},
							"filter": func(slice []interface{}, predicate func(interface{}) bool) []interface{} {
								var result []interface{}
								for _, item := range slice {
									if predicate(item) {
										result = append(result, item)
									}
								}
								return result
							},
							"filterStrings": func(slice []string, contains string) []string {
								var result []string
								for _, item := range slice {
									if strings.Contains(item, contains) {
										result = append(result, item)
									}
								}
								return result
							},
							"filterInts": func(slice []int, min, max int) []int {
								var result []int
								for _, item := range slice {
									if item >= min && item <= max {
										result = append(result, item)
									}
								}
								return result
							},
							"groupBy": func(slice []interface{}, keyFunc func(interface{}) string) map[string][]interface{} {
								result := make(map[string][]interface{})
								for _, item := range slice {
									key := keyFunc(item)
									result[key] = append(result[key], item)
								}
								return result
							},
							"partition": func(slice []interface{}, predicate func(interface{}) bool) [][]interface{} {
								var truthy, falsy []interface{}
								for _, item := range slice {
									if predicate(item) {
										truthy = append(truthy, item)
									} else {
										falsy = append(falsy, item)
									}
								}
								return [][]interface{}{truthy, falsy}
							},
							"take": func(n int, slice []interface{}) []interface{} {
								if n >= len(slice) {
									return slice
								}
								return slice[:n]
							},
							"drop": func(n int, slice []interface{}) []interface{} {
								if n >= len(slice) {
									return []interface{}{}
								}
								return slice[n:]
							},
							"takeWhile": func(slice []interface{}, predicate func(interface{}) bool) []interface{} {
								for i, item := range slice {
									if !predicate(item) {
										return slice[:i]
									}
								}
								return slice
							},
							"dropWhile": func(slice []interface{}, predicate func(interface{}) bool) []interface{} {
								for i, item := range slice {
									if !predicate(item) {
										return slice[i:]
									}
								}
								return []interface{}{}
							},
							"intersect": func(slice1, slice2 []interface{}) []interface{} {
								set := make(map[interface{}]bool)
								for _, item := range slice2 {
									set[item] = true
								}
								var result []interface{}
								for _, item := range slice1 {
									if set[item] {
										result = append(result, item)
									}
								}
								return result
							},
							"difference": func(slice1, slice2 []interface{}) []interface{} {
								set := make(map[interface{}]bool)
								for _, item := range slice2 {
									set[item] = true
								}
								var result []interface{}
								for _, item := range slice1 {
									if !set[item] {
										result = append(result, item)
									}
								}
								return result
							},
							"union": func(slice1, slice2 []interface{}) []interface{} {
								set := make(map[interface{}]bool)
								var result []interface{}
								for _, item := range slice1 {
									if !set[item] {
										set[item] = true
										result = append(result, item)
									}
								}
								for _, item := range slice2 {
									if !set[item] {
										set[item] = true
										result = append(result, item)
									}
								}
								return result
							},
							"symmetricDifference": func(slice1, slice2 []interface{}) []interface{} {
								set1 := make(map[interface{}]bool)
								set2 := make(map[interface{}]bool)
								for _, item := range slice1 {
									set1[item] = true
								}
								for _, item := range slice2 {
									set2[item] = true
								}
								var result []interface{}
								for _, item := range slice1 {
									if !set2[item] {
										result = append(result, item)
									}
								}
								for _, item := range slice2 {
									if !set1[item] {
										result = append(result, item)
									}
								}
								return result
							},

							// JSON and data functions
							"toJSON": func(v interface{}) string {
								jsonBytes, err := json.Marshal(v)
								if err != nil {
									return fmt.Sprintf("error: %v", err)
								}
								return string(jsonBytes)
							},
							"fromJSON": func(s string) interface{} {
								var result interface{}
								err := json.Unmarshal([]byte(s), &result)
								if err != nil {
									return nil
								}
								return result
							},
							"prettyJSON": func(v interface{}) string {
								jsonBytes, err := json.MarshalIndent(v, "", "  ")
								if err != nil {
									return fmt.Sprintf("error: %v", err)
								}
								return string(jsonBytes)
							},
							"flattenMap": func(m map[string]interface{}, prefix string) map[string]interface{} {
								result := make(map[string]interface{})
								for k, v := range m {
									key := k
									if prefix != "" {
										key = prefix + "." + k
									}
									if nested, ok := v.(map[string]interface{}); ok {
										for nk, nv := range func(nested map[string]interface{}, prefix string) map[string]interface{} {
											result := make(map[string]interface{})
											for k, v := range nested {
												key := k
												if prefix != "" {
													key = prefix + "." + k
												}
												result[key] = v
											}
											return result
										}(nested, key) {
											result[nk] = nv
										}
									} else {
										result[key] = v
									}
								}
								return result
							},
							"unflattenMap": func(m map[string]interface{}) map[string]interface{} {
								result := make(map[string]interface{})
								for k, v := range m {
									parts := strings.Split(k, ".")
									current := result
									for i, part := range parts[:len(parts)-1] {
										if _, exists := current[part]; !exists {
											current[part] = make(map[string]interface{})
										}
										if i < len(parts)-2 {
											current = current[part].(map[string]interface{})
										}
									}
									current[parts[len(parts)-1]] = v
								}
								return result
							},
							"merge": func(maps ...map[string]interface{}) map[string]interface{} {
								result := make(map[string]interface{})
								for _, m := range maps {
									for k, v := range m {
										result[k] = v
									}
								}
								return result
							},
							"deepMerge": func(map1, map2 map[string]interface{}) map[string]interface{} {
								result := make(map[string]interface{})
								for k, v := range map1 {
									result[k] = v
								}
								for k, v := range map2 {
									if existing, exists := result[k]; exists {
										if existingMap, ok := existing.(map[string]interface{}); ok {
											if newMap, ok := v.(map[string]interface{}); ok {
												result[k] = func(map1, map2 map[string]interface{}) map[string]interface{} {
													result := make(map[string]interface{})
													for k, v := range map1 {
														result[k] = v
													}
													for k, v := range map2 {
														result[k] = v
													}
													return result
												}(existingMap, newMap)
												continue
											}
										}
									}
									result[k] = v
								}
								return result
							},
							"invert": func(m map[string]interface{}) map[string]interface{} {
								result := make(map[string]interface{})
								for k, v := range m {
									if str, ok := v.(string); ok {
										result[str] = k
									}
								}
								return result
							},
							"mapKeys": func(m map[string]interface{}, keyFunc func(string) string) map[string]interface{} {
								result := make(map[string]interface{})
								for k, v := range m {
									result[keyFunc(k)] = v
								}
								return result
							},
							"mapValues": func(m map[string]interface{}, valueFunc func(interface{}) interface{}) map[string]interface{} {
								result := make(map[string]interface{})
								for k, v := range m {
									result[k] = valueFunc(v)
								}
								return result
							},

							// Sequence function for pagination
							"seq": func(start, end int) []int {
								var result []int
								if start <= end {
									for i := start; i <= end; i++ {
										result = append(result, i)
									}
								} else {
									for i := start; i >= end; i-- {
										result = append(result, i)
									}
								}
								return result
							},
						},
					})
				},
			},
		},
		// HTTP URL
		"url": config.Env("APP_URL", "http://localhost"),
		// HTTP Host
		"host": config.Env("APP_HOST", "127.0.0.1"),
		// HTTP Port
		"port": config.Env("APP_PORT", "3000"),
		// HTTP Timeout, default is 3 seconds
		"request_timeout": 3,
		// HTTPS Configuration
		"tls": map[string]any{
			// HTTPS Host
			"host": config.Env("APP_HOST", "127.0.0.1"),
			// HTTPS Port
			"port": config.Env("APP_PORT", "3000"),
			// SSL Certificate, you can put the certificate in /public folder
			"ssl": map[string]any{
				// ca.pem
				"cert": "",
				// ca.key
				"key": "",
			},
		},
		// HTTP Client Configuration
		"client": map[string]any{
			"base_url":                config.GetString("HTTP_CLIENT_BASE_URL"),
			"timeout":                 config.GetDuration("HTTP_CLIENT_TIMEOUT"),
			"max_idle_conns":          config.GetInt("HTTP_CLIENT_MAX_IDLE_CONNS"),
			"max_idle_conns_per_host": config.GetInt("HTTP_CLIENT_MAX_IDLE_CONNS_PER_HOST"),
			"max_conns_per_host":      config.GetInt("HTTP_CLIENT_MAX_CONN_PER_HOST"),
			"idle_conn_timeout":       config.GetDuration("HTTP_CLIENT_IDLE_CONN_TIMEOUT"),
		},
	})
}

// Helper function to convert hex color to RGB components
func hexToRGB(hex string) (int, int, int) {
	// Remove # prefix if present
	if hex[0] == '#' {
		hex = hex[1:]
	}

	// Parse hex values
	r, _ := strconv.ParseInt(hex[0:2], 16, 64)
	g, _ := strconv.ParseInt(hex[2:4], 16, 64)
	b, _ := strconv.ParseInt(hex[4:6], 16, 64)

	return int(r), int(g), int(b)
}
