package main

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

func runMigrations(db *sql.DB) error {
	// Read migration files from sql/schema/migrations
	files, err := filepath.Glob("sql/schema/migrations/*.sql")
	if err != nil {
		return err
	}

	// Sort files by name to ensure order
	sort.Strings(files)

	// Run each migration
	for _, file := range files {
		migrationContent, err := os.ReadFile(file)
		if err != nil {
			return err
		}

		_, err = db.Exec(string(migrationContent))
		if err != nil {
			return fmt.Errorf("migration %s failed: %w", file, err)
		}

		fmt.Printf("Migration applied: %s\n", file)
	}

	return nil
}
