package main

import (
	"database/sql"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	_ "github.com/lib/pq"
)

type Migration struct {
	Version int
	Name    string
	UpSQL   string
	DownSQL string
}

func main() {
	var (
		dbURL = flag.String("database-url", os.Getenv("DATABASE_URL"), "Database URL")
		dir   = flag.String("dir", "migrations", "Migrations directory")
	)
	flag.Parse()

	if *dbURL == "" {
		log.Fatal("DATABASE_URL is required")
	}

	args := flag.Args()
	if len(args) == 0 {
		log.Fatal("Command required: up, down, reset")
	}

	command := args[0]

	db, err := sql.Open("postgres", *dbURL)
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
	defer db.Close()

	if err := createMigrationsTable(db); err != nil {
		log.Fatal("Failed to create migrations table:", err)
	}

	migrations, err := loadMigrations(*dir)
	if err != nil {
		log.Fatal("Failed to load migrations:", err)
	}

	switch command {
	case "up":
		if err := migrateUp(db, migrations); err != nil {
			log.Fatal("Migration up failed:", err)
		}
	case "down":
		if err := migrateDown(db, migrations); err != nil {
			log.Fatal("Migration down failed:", err)
		}
	case "reset":
		if err := migrateReset(db, migrations); err != nil {
			log.Fatal("Migration reset failed:", err)
		}
	default:
		log.Fatal("Unknown command:", command)
	}
}

func createMigrationsTable(db *sql.DB) error {
	query := `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER PRIMARY KEY,
			applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)
	`
	_, err := db.Exec(query)
	return err
}

func loadMigrations(dir string) ([]Migration, error) {
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var migrations []Migration
	migrationMap := make(map[int]*Migration)

	for _, file := range files {
		if file.IsDir() {
			continue
		}

		name := file.Name()
		if !strings.HasSuffix(name, ".sql") {
			continue
		}

		parts := strings.Split(name, "_")
		if len(parts) < 2 {
			continue
		}

		version, err := strconv.Atoi(parts[0])
		if err != nil {
			continue
		}

		content, err := ioutil.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}

		migration, exists := migrationMap[version]
		if !exists {
			migration = &Migration{
				Version: version,
				Name:    strings.Join(parts[1:], "_"),
			}
			migrationMap[version] = migration
		}

		if strings.Contains(name, ".up.sql") {
			migration.UpSQL = string(content)
		} else if strings.Contains(name, ".down.sql") {
			migration.DownSQL = string(content)
		}
	}

	for _, migration := range migrationMap {
		migrations = append(migrations, *migration)
	}

	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].Version < migrations[j].Version
	})

	return migrations, nil
}

func getAppliedMigrations(db *sql.DB) (map[int]bool, error) {
	rows, err := db.Query("SELECT version FROM schema_migrations")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	applied := make(map[int]bool)
	for rows.Next() {
		var version int
		if err := rows.Scan(&version); err != nil {
			return nil, err
		}
		applied[version] = true
	}

	return applied, nil
}

func migrateUp(db *sql.DB, migrations []Migration) error {
	applied, err := getAppliedMigrations(db)
	if err != nil {
		return err
	}

	for _, migration := range migrations {
		if applied[migration.Version] {
			continue
		}

		log.Printf("Applying migration %d: %s", migration.Version, migration.Name)

		tx, err := db.Begin()
		if err != nil {
			return err
		}

		if _, err := tx.Exec(migration.UpSQL); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %d failed: %v", migration.Version, err)
		}

		if _, err := tx.Exec("INSERT INTO schema_migrations (version) VALUES ($1)", migration.Version); err != nil {
			tx.Rollback()
			return err
		}

		if err := tx.Commit(); err != nil {
			return err
		}

		log.Printf("Migration %d applied successfully", migration.Version)
	}

	return nil
}

func migrateDown(db *sql.DB, migrations []Migration) error {
	applied, err := getAppliedMigrations(db)
	if err != nil {
		return err
	}

	// Find the latest applied migration
	var latestVersion int
	for version := range applied {
		if version > latestVersion {
			latestVersion = version
		}
	}

	if latestVersion == 0 {
		log.Println("No migrations to rollback")
		return nil
	}

	// Find the migration to rollback
	var migration *Migration
	for _, m := range migrations {
		if m.Version == latestVersion {
			migration = &m
			break
		}
	}

	if migration == nil {
		return fmt.Errorf("migration %d not found", latestVersion)
	}

	log.Printf("Rolling back migration %d: %s", migration.Version, migration.Name)

	tx, err := db.Begin()
	if err != nil {
		return err
	}

	if _, err := tx.Exec(migration.DownSQL); err != nil {
		tx.Rollback()
		return fmt.Errorf("rollback %d failed: %v", migration.Version, err)
	}

	if _, err := tx.Exec("DELETE FROM schema_migrations WHERE version = $1", migration.Version); err != nil {
		tx.Rollback()
		return err
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	log.Printf("Migration %d rolled back successfully", migration.Version)
	return nil
}

func migrateReset(db *sql.DB, migrations []Migration) error {
	applied, err := getAppliedMigrations(db)
	if err != nil {
		return err
	}

	// Rollback all migrations in reverse order
	for i := len(migrations) - 1; i >= 0; i-- {
		migration := migrations[i]
		if !applied[migration.Version] {
			continue
		}

		log.Printf("Rolling back migration %d: %s", migration.Version, migration.Name)

		tx, err := db.Begin()
		if err != nil {
			return err
		}

		if _, err := tx.Exec(migration.DownSQL); err != nil {
			tx.Rollback()
			return fmt.Errorf("rollback %d failed: %v", migration.Version, err)
		}

		if _, err := tx.Exec("DELETE FROM schema_migrations WHERE version = $1", migration.Version); err != nil {
			tx.Rollback()
			return err
		}

		if err := tx.Commit(); err != nil {
			return err
		}
	}

	log.Println("All migrations rolled back successfully")
	return nil
}