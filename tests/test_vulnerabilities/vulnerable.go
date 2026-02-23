package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"unsafe"

	"crypto/md5"
	"crypto/tls"
	"html/template"
	"math/rand"
)

// Vulnerability 1: SQL injection via string concatenation (CWE-89)
func getUser(db *sql.DB, userID string) (*sql.Rows, error) {
	query := "SELECT * FROM users WHERE id = '" + userID + "'"
	return db.Query(query)
}

// Vulnerability 2: SQL injection via fmt.Sprintf (CWE-89)
func searchUsers(db *sql.DB, name string) (*sql.Rows, error) {
	query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name)
	return db.Query(query)
}

// Vulnerability 3: Command injection via shell (CWE-78)
func runCommand(userInput string) ([]byte, error) {
	return exec.Command("sh", "-c", "echo "+userInput).Output()
}

// Vulnerability 4: Command injection via string concatenation (CWE-78)
func executeScript(script string) ([]byte, error) {
	cmd := "./scripts/" + script
	return exec.Command("bash", "-c", cmd).Output()
}

// Vulnerability 5: Hardcoded API key (CWE-798)
const APIKey = "sk-1234567890abcdef1234567890abcdef12345678"

// Vulnerability 6: Hardcoded password (CWE-798)
const Password = "super_secret_password_123"

// Vulnerability 7: Hardcoded token (CWE-798)
var secretToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"

// Vulnerability 8: Insecure TLS config (CWE-295)
func getInsecureTLS() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
	}
}

// Vulnerability 9: Path traversal via http.ServeFile (CWE-22)
func serveUserFile(w http.ResponseWriter, r *http.Request) {
	filename := r.FormValue("file")
	http.ServeFile(w, r, "/var/www/uploads/"+filename)
}

// Vulnerability 10: Path traversal via file concatenation (CWE-22)
func readUserFile(filename string) ([]byte, error) {
	return os.ReadFile("/var/www/uploads/" + filename)
}

// Vulnerability 11: Weak crypto MD5 (CWE-327)
func hashPassword(password string) string {
	hash := md5.Sum([]byte(password))
	return fmt.Sprintf("%x", hash)
}

// Vulnerability 12: Insecure random (CWE-338)
func generateToken() int {
	return rand.Intn(1000000)
}

// Vulnerability 13: Insecure random seed (CWE-338)
func init() {
	rand.Seed(12345)
}

// Vulnerability 14: XSS via template.HTML (CWE-79)
func renderUserContent(w http.ResponseWriter, r *http.Request) {
	content := r.FormValue("content")
	html := template.HTML(content)
	fmt.Fprint(w, html)
}

// Vulnerability 15: Defer in loop (Logic error / CWE-772)
func processFiles(files []string) {
	for _, file := range files {
		f, _ := os.Open(file)
		defer f.Close()
	}
}

// Vulnerability 16: File permission 0777 (CWE-732)
func createTempDir(path string) error {
	return os.MkdirAll(path, 0777)
}

// Vulnerability 17: Hardcoded database connection string (CWE-798)
func getDBConnection() string {
	return "postgres://admin:secretpassword@localhost:5432/production"
}

// Vulnerability 18: json.Unmarshal without validation (CWE-502)
func parseUserData(data []byte, user *User) error {
	return json.Unmarshal(data, user)
}

// Vulnerability 19: http.ListenAndServe without TLS (CWE-319)
func startServer() {
	http.ListenAndServe(":8080", nil)
}

// Vulnerability 20: Unsafe package usage (CWE-466)
func unsafeCast(ptr unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(uintptr(ptr) + 1)
}

// Vulnerability 21: Insecure HTTP GET (CWE-319)
func fetchData() (*http.Response, error) {
	return http.Get("http://api.example.com/data")
}

// Vulnerability 22: Binding to all interfaces (CWE-1327)
func startServerAllInterfaces() error {
	return http.ListenAndServe(":9000", nil)
}

// User struct for JSON parsing
type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
}

func main() {
	fmt.Println("Vulnerable Go application for testing")
}
