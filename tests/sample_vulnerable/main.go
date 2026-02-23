// Vulnerable Go Application - For Testing Purposes
// This file contains intentional security vulnerabilities for testing Secure Vibe MCP

package main

import (
	"crypto/md5"
	"crypto/sha1"
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

var db *sql.DB

func init() {
	var err error
	db, err = sql.Open("sqlite3", "./app.db")
	if err != nil {
		panic(err)
	}
}

// ============================================
// VULNERABILITY 1: SQL Injection (SEC-002)
// ============================================
func getUser(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("id")

	// DANGEROUS: String concatenation in SQL query
	query := "SELECT * FROM users WHERE id = " + userID  // SEC-002: SQL Injection

	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	// Process results...
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

// ============================================
// VULNERABILITY 2: SQL Injection via fmt.Sprintf (SEC-002)
// ============================================
func searchUsers(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")

	// DANGEROUS: Using fmt.Sprintf for SQL
	query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name)  // SEC-002

	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

// ============================================
// VULNERABILITY 3: Command Injection (SEC-003)
// ============================================
func pingHost(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")

	// DANGEROUS: User input in command execution
	cmd := exec.Command("ping", "-c", "4", host)  // SEC-003: Command Injection
	output, err := cmd.CombinedOutput()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Write(output)
}

// ============================================
// VULNERABILITY 4: Command Injection via sh -c (SEC-003)
// ============================================
func runCommand(w http.ResponseWriter, r *http.Request) {
	command := r.FormValue("command")

	// DANGEROUS: Executing user-controlled command
	cmd := exec.Command("sh", "-c", command)  // SEC-003: Command Injection
	output, err := cmd.CombinedOutput()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Write(output)
}

// ============================================
// VULNERABILITY 5: Weak Hash Algorithms (SEC-015)
// ============================================
func hashData(w http.ResponseWriter, r *http.Request) {
	data := r.FormValue("data")

	// DANGEROUS: Using MD5
	md5Hash := fmt.Sprintf("%x", md5.Sum([]byte(data)))  // SEC-015: MD5

	// DANGEROUS: Using SHA1
	sha1Hash := fmt.Sprintf("%x", sha1.Sum([]byte(data)))  // SEC-015: SHA1

	json.NewEncoder(w).Encode(map[string]string{
		"md5":  md5Hash,
		"sha1": sha1Hash,
	})
}

// ============================================
// VULNERABILITY 6: Insecure Random (SEC-017)
// ============================================
func generateToken(w http.ResponseWriter, r *http.Request) {
	// DANGEROUS: math/rand is not cryptographically secure
	rand.Seed(time.Now().UnixNano())
	token := fmt.Sprintf("%d", rand.Int())  // SEC-017: Insecure Random

	json.NewEncoder(w).Encode(map[string]string{"token": token})
}

// ============================================
// VULNERABILITY 7: Path Traversal (SEC-035)
// ============================================
func downloadFile(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("filename")

	// DANGEROUS: No path validation
	filePath := filepath.Join("./uploads", filename)  // SEC-035: Path Traversal

	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Write(data)
}

// ============================================
// VULNERABILITY 8: Hardcoded Secrets (SEC-016, SEC-025)
// ============================================
const (
	APIKey     = "sk_live_51HYs2jJq3dKl4p9mN"     // SEC-016: Hardcoded API Key
	SecretKey  = "my-super-secret-key-12345"     // SEC-016: Hardcoded Secret
	DBPassword = "password123"                   // SEC-025: Hardcoded Credentials
)

func getAPIClient() string {
	// Using hardcoded secret
	return APIKey
}

// ============================================
// VULNERABILITY 9: Template Injection (SEC-008)
// ============================================
func renderTemplate(w http.ResponseWriter, r *http.Request) {
	tmplStr := r.FormValue("template")

	// DANGEROUS: User-controlled template
	tmpl, err := template.New("dynamic").Parse(tmplStr)  // SEC-008: SSTI
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	tmpl.Execute(w, nil)
}

// ============================================
// VULNERABILITY 10: SSRF (SEC-031)
// ============================================
func fetchURL(w http.ResponseWriter, r *http.Request) {
	url := r.FormValue("url")

	// DANGEROUS: Server-Side Request Forgery
	resp, err := http.Get(url)  // SEC-031: SSRF
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	w.Write(body)
}

// ============================================
// VULNERABILITY 11: Open Redirect (SEC-032)
// ============================================
func redirectUser(w http.ResponseWriter, r *http.Request) {
	url := r.URL.Query().Get("url")

	// DANGEROUS: Unvalidated redirect
	http.Redirect(w, r, url, http.StatusFound)  // SEC-032: Open Redirect
}

// ============================================
// VULNERABILITY 12: Regex DoS (SEC-044)
// ============================================
func validateEmail(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")

	// DANGEROUS: Regex vulnerable to ReDoS
	re := regexp.MustCompile(`^([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})*$`)  // SEC-044: ReDoS

	isValid := re.MatchString(email)
	json.NewEncoder(w).Encode(map[string]bool{"valid": isValid})
}

// ============================================
// VULNERABILITY 13: Information Disclosure (SEC-030)
// ============================================
func debugInfo(w http.ResponseWriter, r *http.Request) {
	// DANGEROUS: Exposing debug information
	info := map[string]interface{}{
		"go_version":   "1.21",
		"environment":  os.Environ(),  // SEC-030: Environment exposure
		"stack_trace":  getStackTrace(), // SEC-030: Stack trace
	}

	json.NewEncoder(w).Encode(info)
}

func getStackTrace() string {
	// Simulated stack trace
	return "goroutine 1 [running]:\nmain.debugInfo(...)"
}

// ============================================
// VULNERABILITY 14: Insecure Deserialization (SEC-026)
// ============================================
import "encoding/gob"

func processData(w http.ResponseWriter, r *http.Request) {
	data, _ := ioutil.ReadAll(r.Body)

	// DANGEROUS: Insecure deserialization
	var obj interface{}
	gob.NewDecoder(r.Body).Decode(&obj)  // SEC-026: Insecure Deserialization

	json.NewEncoder(w).Encode(map[string]string{"status": "processed"})
}

// ============================================
// VULNERABILITY 15: Race Condition (SEC-045)
// ============================================
var counter int

func incrementCounter(w http.ResponseWriter, r *http.Request) {
	// DANGEROUS: Race condition - no synchronization
	counter++  // SEC-045: Race Condition

	json.NewEncoder(w).Encode(map[string]int{"counter": counter})
}

// ============================================
// VULNERABILITY 16: Weak Password Hashing (SEC-019, SEC-021)
// ============================================
func hashPassword(password string) string {
	// DANGEROUS: No salt, weak algorithm
	hash := sha1.Sum([]byte(password))  // SEC-015, SEC-019, SEC-021
	return fmt.Sprintf("%x", hash)
}

// ============================================
// VULNERABILITY 17: Insecure File Permissions (SEC-039)
// ============================================
func createTempFile(w http.ResponseWriter, r *http.Request) {
	filename := r.FormValue("filename")
	path := filepath.Join("/tmp", filename)

	// DANGEROUS: World-writable file
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0777)  // SEC-039: Unsafe Permissions
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer file.Close()

	json.NewEncoder(w).Encode(map[string]string{"status": "created", "path": path})
}

// ============================================
// VULNERABILITY 18: Integer Overflow (SEC-047)
// ============================================
func allocateBuffer(w http.ResponseWriter, r *http.Request) {
	sizeStr := r.FormValue("size")
	var size int
	fmt.Sscanf(sizeStr, "%d", &size)

	// DANGEROUS: Potential integer overflow leading to buffer issues
	buffer := make([]byte, size)  // SEC-047: Integer Overflow

	json.NewEncoder(w).Encode(map[string]int{"allocated": len(buffer)})
}

// ============================================
// VULNERABILITY 19: TOCTOU (SEC-046)
// ============================================
func readFileSafe(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("filename")
	path := filepath.Join("./uploads", filename)

	// DANGEROUS: TOCTOU - checking and using in separate operations
	if _, err := os.Stat(path); err == nil {  // Check
		data, err := ioutil.ReadFile(path)     // Use
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(data)
	}
}

// ============================================
// VULNERABILITY 20: Unvalidated Input in filepath (SEC-035)
// ============================================
func deleteFile(w http.ResponseWriter, r *http.Request) {
	filename := r.FormValue("filename")

	// DANGEROUS: Direct use of user input
	os.Remove(filename)  // SEC-035: Path Traversal / Unrestricted Deletion

	json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
}

// ============================================
// Additional vulnerable patterns
// ============================================

// DANGEROUS: Using exec.Command with shell
func dangerousExec(input string) {
	exec.Command("sh", "-c", input).Run()  // SEC-003
}

// DANGEROUS: Insecure temporary file
func insecureTemp() {
	f, _ := os.Create("/tmp/tempfile.txt")
	f.Chmod(0777)  // SEC-039
	defer f.Close()
}

// DANGEROUS: Using ioutil.WriteFile with insecure permissions
func writeConfig(data []byte) {
	ioutil.WriteFile("config.txt", data, 0644)  // SEC-039
}

// ============================================
// Main function
// ============================================
func main() {
	fmt.Println("⚠️  WARNING: This application contains intentional security vulnerabilities!")
	fmt.Println("🔒 Use only for testing Secure Vibe MCP scanner")
	fmt.Println()

	http.HandleFunc("/api/user", getUser)
	http.HandleFunc("/api/search", searchUsers)
	http.HandleFunc("/api/ping", pingHost)
	http.HandleFunc("/api/run", runCommand)
	http.HandleFunc("/api/hash", hashData)
	http.HandleFunc("/api/token", generateToken)
	http.HandleFunc("/api/download", downloadFile)
	http.HandleFunc("/api/render", renderTemplate)
	http.HandleFunc("/api/fetch", fetchURL)
	http.HandleFunc("/api/redirect", redirectUser)
	http.HandleFunc("/api/validate", validateEmail)
	http.HandleFunc("/api/debug", debugInfo)
	http.HandleFunc("/api/process", processData)
	http.HandleFunc("/api/counter", incrementCounter)
	http.HandleFunc("/api/temp", createTempFile)
	http.HandleFunc("/api/allocate", allocateBuffer)
	http.HandleFunc("/api/read", readFileSafe)
	http.HandleFunc("/api/delete", deleteFile)

	fmt.Println("Server starting on :8080")
	http.ListenAndServe(":8080", nil)
}
