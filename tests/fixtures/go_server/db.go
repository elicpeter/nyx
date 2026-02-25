package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"os/exec"
)

// ───── Database initialization ─────

// InitDB opens a database connection using credentials from environment.
// VULN: os.Getenv flows into db.Exec for schema setup
func InitDB() (*sql.DB, error) {
	dsn := os.Getenv("DATABASE_DSN")
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}

	// Run schema setup from env
	schema := os.Getenv("SCHEMA_SQL")
	_, err = db.Exec(schema)
	if err != nil {
		log.Printf("schema setup failed: %v", err)
	}

	return db, nil
}

// ───── Data export ─────

// ExportTable dumps a table to CSV using pg_dump.
// VULN: os.Getenv flows into exec.Command (command injection)
func ExportTable(tableName string) error {
	dbURL := os.Getenv("DATABASE_URL")
	dumpCmd := fmt.Sprintf("pg_dump --table=%s --format=csv %s", tableName, dbURL)
	out, err := exec.Command("sh", "-c", dumpCmd).Output()
	if err != nil {
		return fmt.Errorf("export failed: %w", err)
	}
	log.Printf("Exported %d bytes", len(out))
	return nil
}

// ───── Audit logging ─────

// LogAuditEvent writes an audit record using env-driven SQL.
// VULN: os.Getenv flows into db.Exec
func LogAuditEvent(db *sql.DB, event string) error {
	tableName := os.Getenv("AUDIT_TABLE")
	query := fmt.Sprintf("INSERT INTO %s (event, ts) VALUES ('%s', NOW())", tableName, event)
	_, err := db.Exec(query)
	return err
}

// ───── Health check ─────

// CheckDependencies pings all external services.
// VULN: os.Getenv flows into exec.Command
func CheckDependencies() error {
	endpoints := []string{
		os.Getenv("REDIS_HOST"),
		os.Getenv("KAFKA_HOST"),
		os.Getenv("ELASTICSEARCH_HOST"),
	}
	for _, ep := range endpoints {
		cmd := exec.Command("nc", "-z", ep, "6379")
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("dependency %s unreachable: %w", ep, err)
		}
	}
	return nil
}
