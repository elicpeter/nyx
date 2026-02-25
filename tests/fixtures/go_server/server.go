package main

import (
	"database/sql"
	"fmt"
	"html"
	"html/template"
	"log"
	"net/http"
	"os"
	"os/exec"
)

// ───── Handler: Execute system command from env ─────

// GET /admin/run
// Reads a maintenance command from the environment and executes it.
// VULN: os.Getenv flows into exec.Command (command injection)
func handleAdminRun(w http.ResponseWriter, r *http.Request) {
	maintenanceCmd := os.Getenv("MAINTENANCE_CMD")
	out, err := exec.Command("bash", "-c", maintenanceCmd).Output()
	if err != nil {
		http.Error(w, "command failed: "+err.Error(), 500)
		return
	}
	fmt.Fprintf(w, "Output: %s", out)
}

// ───── Handler: Deploy from env config ─────

// POST /admin/deploy
// Constructs a deploy command from multiple env vars.
// VULN: os.Getenv flows into exec.Command
func handleDeploy(w http.ResponseWriter, r *http.Request) {
	target := os.Getenv("DEPLOY_TARGET")
	branch := os.Getenv("DEPLOY_BRANCH")
	cmd := fmt.Sprintf("cd /opt/app && git checkout %s && ./deploy.sh %s", branch, target)
	out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
	if err != nil {
		log.Printf("deploy failed: %s\n%s", err, out)
		http.Error(w, "deploy failed", 500)
		return
	}
	fmt.Fprintf(w, "Deployed %s to %s", branch, target)
}

// ───── Handler: Database query from env ─────

// GET /admin/db-check
// Runs a diagnostic SQL query read from environment.
// VULN: os.Getenv flows into db.Query (SQL injection)
func handleDBCheck(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		diagnosticQuery := os.Getenv("DIAGNOSTIC_QUERY")
		rows, err := db.Query(diagnosticQuery)
		if err != nil {
			http.Error(w, "query failed: "+err.Error(), 500)
			return
		}
		defer rows.Close()
		fmt.Fprintln(w, "Query executed successfully")
	}
}

// ───── Handler: Database exec from env ─────

// POST /admin/db-migrate
// Runs a migration statement from environment config.
// VULN: os.Getenv flows into db.Exec (SQL injection)
func handleDBMigrate(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		migration := os.Getenv("MIGRATION_SQL")
		_, err := db.Exec(migration)
		if err != nil {
			http.Error(w, "migration failed: "+err.Error(), 500)
			return
		}
		fmt.Fprintln(w, "Migration complete")
	}
}

// ───── Handler: Safe output (HTML escaped) ─────

// GET /api/greet
// SAFE: user input properly escaped with html.EscapeString
func handleGreet(w http.ResponseWriter, r *http.Request) {
	name := os.Getenv("DEFAULT_GREETING")
	safeName := html.EscapeString(name)
	fmt.Fprintf(w, "<h1>Hello, %s</h1>", safeName)
}

// ───── Handler: Safe URL encoding ─────

// GET /api/safe-redirect
// SAFE: URL properly escaped with url.QueryEscape before use
func handleSafeRedirect(w http.ResponseWriter, r *http.Request) {
	// This would use url.QueryEscape in real code
	target := os.Getenv("REDIRECT_URL")
	safeTarget := template.HTMLEscapeString(target)
	http.Redirect(w, r, "/go?url="+safeTarget, http.StatusFound)
}

func main() {
	http.HandleFunc("/admin/run", handleAdminRun)
	http.HandleFunc("/admin/deploy", handleDeploy)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
