package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

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

type User struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
}

const userFilePath = "users.json"

// Load users from users.json
func loadUsers() ([]User, error) {
	var users []User
	file, err := ioutil.ReadFile(userFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			err = ioutil.WriteFile(userFilePath, []byte("[]"), 0644)
			if err != nil {
				return nil, err
			}
			return users, nil
		}
		return nil, err
	}
	if len(file) == 0 {
		err = ioutil.WriteFile(userFilePath, []byte("[]"), 0644)
		if err != nil {
			return nil, err
		}
		return users, nil
	}
	err = json.Unmarshal(file, &users)
	return users, err
}

// Save users to users.json
func saveUsers(users []User) error {
	data, err := json.MarshalIndent(users, "", "  ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(userFilePath, data, 0644)
}

// Register a new user
func registerUser(username, password string) error {
	users, err := loadUsers()
	if err != nil {
		return err
	}
	for _, user := range users {
		if user.Username == username {
			return fmt.Errorf("user already exists")
		}
	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	users = append(users, User{Username: username, PasswordHash: string(hashedPassword)})
	return saveUsers(users)
}

// Authenticate a user
func authenticateUser(username, password string) bool {
	users, err := loadUsers()
	if err != nil {
		fmt.Println("Error loading users:", err)
		return false
	}
	for _, user := range users {
		if user.Username == username {
			err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
			if err == nil {
				return true
			}
			break
		}
	}
	return false
}

// Display menu and get user choice
func displayMenu() int {
	fmt.Println("\nEagleDeploy Menu:")
	fmt.Println("1. Execute a Playbook")
	fmt.Println("2. List YAML Files")
	fmt.Println("3. Manage Inventory")
	fmt.Println("4. Enable/Disable Detailed Logging")
	fmt.Println("5. Rollback Changes")
	fmt.Println("6. Show Help")
	fmt.Println("0. Exit")
	fmt.Print("Select an option: ")

	var choice int
	fmt.Scanln(&choice)
	return choice
}

// Execute a YAML playbook
func executeYAML(ymlFilePath string, targetHosts []string) {
	data, err := ioutil.ReadFile(ymlFilePath)
	if err != nil {
		log.Fatalf("Error reading YAML file: %v", err)
	}
	var playbook Playbook
	err = yaml.Unmarshal(data, &playbook)
	if err != nil {
		log.Fatalf("Error parsing YAML file: %v", err)
	}
	hosts := playbook.Hosts
	if len(targetHosts) > 0 {
		hosts = targetHosts
	}
	fmt.Printf("Executing Playbook: %s (Version: %s) on Hosts: %v\n", playbook.Name, playbook.Version, hosts)
	for _, task := range playbook.Tasks {
		fmt.Printf("Executing Task: %s\n", task.Name)
		cmd := exec.Command("bash", "-c", task.Command)
		output, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Printf("Error executing task '%s': %v\n", task.Name, err)
		} else {
			fmt.Printf("Output of '%s':\n%s\n", task.Name, string(output))
		}
	}
}

// List YAML files based on a keyword
func listYAMLFiles(keyword string) {
	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml") {
			if strings.Contains(path, keyword) {
				fmt.Println("Found YAML file:", path)
			}
		}
		return nil
	})
	if err != nil {
		log.Fatalf("Error listing YAML files: %v", err)
	}
}

// Main function
func main() {
	fmt.Println("Welcome to EagleDeploy CLI Auth!")
	fmt.Println("1. Register")
	fmt.Println("2. Login")
	fmt.Print("Choose an option: ")
	var choice int
	fmt.Scan(&choice)

	var username, password string
	switch choice {
	case 1:
		fmt.Print("Enter username: ")
		fmt.Scan(&username)
		fmt.Print("Enter password: ")
		fmt.Scan(&password)
		if err := registerUser(username, password); err != nil {
			fmt.Println("Registration error:", err)
		} else {
			fmt.Println("Registration successful!")
		}
	case 2:
		fmt.Print("Enter username: ")
		fmt.Scan(&username)
		fmt.Print("Enter password: ")
		fmt.Scan(&password)
		if authenticateUser(username, password) {
			fmt.Println("Login successful!")
			// After login, display main menu
			reader := bufio.NewReader(os.Stdin)
			var targetHosts []string
			for {
				choice := displayMenu()
				switch choice {
				case 1:
					fmt.Print("Enter YAML file path: ")
					ymlFilePath, _ := reader.ReadString('\n')
					ymlFilePath = strings.TrimSpace(ymlFilePath)
					executeYAML(ymlFilePath, targetHosts)
				case 2:
					fmt.Print("Enter keyword for YAML files: ")
					keyword, _ := reader.ReadString('\n')
					keyword = strings.TrimSpace(keyword)
					listYAMLFiles(keyword)
				case 0:
					fmt.Println("Exiting EagleDeploy.")
					return
				default:
					fmt.Println("Invalid choice.")
				}
			}
		} else {
			fmt.Println("Invalid username or password.")
		}
	default:
		fmt.Println("Invalid choice.")
	}
}
