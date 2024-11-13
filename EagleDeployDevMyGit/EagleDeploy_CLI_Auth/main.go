package main

import (
	"bufio"
	"database/sql"
	"fmt"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/bcrypt"
	_ "github.com/mattn/go-sqlite3"
)

// Structs for the YAML structure
type Task struct {
	Name    string `yaml:"name"`
	Command string `yaml:"command"`
}
type Playbook struct {
	Name     string   `yaml:"name"`
	Version  string   `yaml:"version"`
	Tasks    []Task   `yaml:"tasks"`
	Hosts    []string `yaml:"hosts"`
	Settings map[string]int `yaml:"settings"`
}

func main() {
	// Initialize the database connection
	db, err := sql.Open("sqlite3", "./users.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Ensure the users table exists
	createUserTable(db)

	// Display main menu for registration and login
	fmt.Println("Welcome to EagleDeploy CLI!")
	fmt.Println("1. Register")
	fmt.Println("2. Login")
	fmt.Print("Choose an option: ")
	var choice int
	fmt.Scan(&choice)

	switch choice {
	case 1:
		if registerUser(db) {
			fmt.Println("Registration successful. You can now log in.")
		}
	case 2:
		if authenticateUser(db) {
			fmt.Println("Login successful. Welcome!")
			mainMenu()
		} else {
			fmt.Println("Login failed.")
		}
	default:
		fmt.Println("Invalid choice.")
	}
}

// Create users table if it doesn't exist
func createUserTable(db *sql.DB) {
	_, err := db.Exec(`
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL
	);
	`)
	if err != nil {
		log.Fatal("Failed to create users table:", err)
	}
}

// Register a new user
func registerUser(db *sql.DB) bool {
	var username, password string
	fmt.Print("Enter new username: ")
	fmt.Scan(&username)
	fmt.Print("Enter new password: ")
	fmt.Scan(&password)

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		fmt.Println("Error hashing password:", err)
		return false
	}

	// Insert the new user into the database
	_, err = db.Exec("INSERT INTO users (username, password_hash) VALUES (?, ?)", username, hashedPassword)
	if err != nil {
		fmt.Println("Error saving user:", err)
		return false
	}

	return true
}

// Authenticate a user
func authenticateUser(db *sql.DB) bool {
	var username, password string
	fmt.Print("Enter username: ")
	fmt.Scan(&username)
	fmt.Print("Enter password: ")
	fmt.Scan(&password)

	var passwordHash string
	err := db.QueryRow("SELECT password_hash FROM users WHERE username = ?", username).Scan(&passwordHash)
	if err != nil {
		fmt.Println("User not found or database error:", err)
		return false
	}

	// Verify password
	err = bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password))
	if err != nil {
		fmt.Println("Incorrect password.")
		return false
	}

	return true
}

// Main menu to execute playbook after login
func mainMenu() {
	fmt.Println("Main Menu")
	fmt.Println("1. Execute Playbook")
	fmt.Println("2. Exit")
	fmt.Print("Choose an option: ")

	var option int
	fmt.Scan(&option)
	switch option {
	case 1:
		runPlaybook()
	case 2:
		fmt.Println("Exiting.")
		os.Exit(0)
	default:
		fmt.Println("Invalid option.")
	}
}

// Run the playbook from playbook.yaml
func runPlaybook() {
	playbook, err := parsePlaybook("playbook.yaml")
	if err != nil {
		log.Fatalf("Failed to parse playbook: %v", err)
	}
	fmt.Printf("Executing playbook: %s (version %s)\n", playbook.Name, playbook.Version)

	for _, task := range playbook.Tasks {
		fmt.Printf("Running task: %s\n", task.Name)
		runTask(task.Command)
	}
}

// Parse playbook.yaml
func parsePlaybook(filename string) (*Playbook, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %v", err)
	}
	var playbook Playbook
	err = yaml.Unmarshal(data, &playbook)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal yaml: %v", err)
	}
	return &playbook, nil
}

// Run a shell command as part of a task
func runTask(command string) {
	cmd := exec.Command("sh", "-c", command)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Printf("Failed to run task: %v\n", err)
	}
}
