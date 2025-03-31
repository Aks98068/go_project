package Signups

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
)

var DB *sql.DB

// JWT secret key
var JwtSecretKey = []byte("your_secret_key_here") // In production, use an environment variable

// Initialize DB connection
func InitDB(database *sql.DB) {
	DB = database
}

func hashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

func Signup(c *gin.Context) {
	// Get form values - note the field names should match what's in your signup form
	username := c.PostForm("username")
	email := c.PostForm("email")
	password := c.PostForm("password")
	confirmPassword := c.PostForm("confirm_password")
	role := c.PostForm("role")

	// Default role if not provided or invalid
	if role != "admin" && role != "user" {
		role = "user" // Default to "user" role
	}

	// If trying to create an admin account
	if role == "admin" {
		// Check if the current user is an admin
		currentRole, exists := c.Get("role")
		if !exists || currentRole != "admin" {
			c.HTML(http.StatusForbidden, "signup.html", gin.H{
				"Title": "Sign Up",
				"Error": "Only existing admins can create admin accounts",
			})
			return
		}

		// Check if we've reached the limit of 5 admin users
		var adminCount int
		err := DB.QueryRow("SELECT COUNT(*) FROM accounts WHERE role = 'admin'").Scan(&adminCount)
		if err != nil {
			log.Printf("Database error while checking admin count: %v", err)
			c.HTML(http.StatusInternalServerError, "signup.html", gin.H{
				"Title": "Sign Up",
				"Error": "An error occurred. Please try again later.",
			})
			return
		}

		if adminCount >= 5 {
			c.HTML(http.StatusForbidden, "signup.html", gin.H{
				"Title": "Sign Up",
				"Error": "Maximum limit of 5 admin users has been reached",
			})
			return
		}
	}

	// Validate inputs
	if username == "" || email == "" || password == "" {
		c.HTML(http.StatusBadRequest, "signup.html", gin.H{
			"Title": "Sign Up",
			"Error": "All fields are required",
		})
		return
	}

	// Check if passwords match
	if password != confirmPassword {
		c.HTML(http.StatusBadRequest, "signup.html", gin.H{
			"Title": "Sign Up",
			"Error": "Passwords do not match",
		})
		return
	}

	// Check if DB is initialized
	if DB == nil {
		log.Println("Database connection is not initialized")
		c.HTML(http.StatusInternalServerError, "signup.html", gin.H{
			"Title": "Sign Up",
			"Error": "Server error. Please try again later.",
		})
		return
	}

	// Check if username already exists
	var count int
	err := DB.QueryRow("SELECT COUNT(*) FROM accounts WHERE username = ?", username).Scan(&count)
	if err != nil {
		log.Printf("Database error while checking username: %v", err)
		c.HTML(http.StatusInternalServerError, "signup.html", gin.H{
			"Title": "Sign Up",
			"Error": "An error occurred. Please try again later.",
		})
		return
	}

	if count > 0 {
		c.HTML(http.StatusConflict, "signup.html", gin.H{
			"Title": "Sign Up",
			"Error": "Username already exists",
		})
		return
	}

	// Check if email already exists
	err = DB.QueryRow("SELECT COUNT(*) FROM accounts WHERE email = ?", email).Scan(&count)
	if err != nil {
		log.Printf("Database error while checking email: %v", err)
		c.HTML(http.StatusInternalServerError, "signup.html", gin.H{
			"Title": "Sign Up",
			"Error": "An error occurred. Please try again later.",
		})
		return
	}

	if count > 0 {
		c.HTML(http.StatusConflict, "signup.html", gin.H{
			"Title": "Sign Up",
			"Error": "Email already registered",
		})
		return
	}

	// Hash the password
	hashedPassword, err := hashPassword(password)
	if err != nil {
		log.Printf("Error hashing password: %v", err)
		c.HTML(http.StatusInternalServerError, "signup.html", gin.H{
			"Title": "Sign Up",
			"Error": "An error occurred. Please try again later.",
		})
		return
	}

	// Insert the new user
	_, err = DB.Exec("INSERT INTO accounts (username, email, password, role) VALUES (?, ?, ?, ?)",
		username, email, hashedPassword, role)
	if err != nil {
		log.Printf("Database error while inserting user: %v", err)
		c.HTML(http.StatusInternalServerError, "signup.html", gin.H{
			"Title": "Sign Up",
			"Error": "An error occurred. Please try again later.",
		})
		return
	}

	// Redirect to login page with success message
	c.Redirect(http.StatusSeeOther, "/login")
}

func Login(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")

	// Validate inputs
	if username == "" || password == "" {
		c.HTML(http.StatusBadRequest, "login.html", gin.H{
			"Title": "Login",
			"Error": "Username and password are required",
		})
		return
	}

	// Check if DB is initialized
	if DB == nil {
		log.Println("Database connection is not initialized")
		c.HTML(http.StatusInternalServerError, "login.html", gin.H{
			"Title": "Login",
			"Error": "Server error. Please try again later.",
		})
		return
	}

	var id int
	var storedUsername, storedPassword, email, role string

	// Query the database for the user
	err := DB.QueryRow("SELECT id, username, password, email, role FROM accounts WHERE username = ?", username).Scan(
		&id, &storedUsername, &storedPassword, &email, &role)

	if err != nil {
		if err == sql.ErrNoRows {
			c.HTML(http.StatusUnauthorized, "login.html", gin.H{
				"Title": "Login",
				"Error": "Invalid username or password",
			})
			return
		}
		log.Printf("Database error: %v", err)
		c.HTML(http.StatusInternalServerError, "login.html", gin.H{
			"Title": "Login",
			"Error": "An error occurred. Please try again later.",
		})
		return
	}

	// Compare the stored hashed password with the provided password
	err = bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(password))
	if err != nil {
		c.HTML(http.StatusUnauthorized, "login.html", gin.H{
			"Title": "Login",
			"Error": "Invalid username or password",
		})
		return
	}

	// Create claims for JWT
	claims := jwt.MapClaims{
		"id":       id,
		"username": username,
		"email":    email,
		"role":     role,
		"exp":      time.Now().Add(time.Hour * 24).Unix(),
	}

	// Create the token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Generate the token string
	tokenString, err := token.SignedString(JwtSecretKey)
	if err != nil {
		log.Printf("Error signing token: %v", err)
		c.HTML(http.StatusInternalServerError, "login.html", gin.H{
			"Title": "Login",
			"Error": "An error occurred. Please try again later.",
		})
		return
	}

	// Set token as cookie
	c.SetCookie(
		"auth_token",
		tokenString,
		3600*24, // 1 day
		"/",
		"",
		false,
		true,
	)

	// Redirect based on role
	if role == "admin" {
		c.Redirect(http.StatusSeeOther, "/adminAccount") // Admin account page
	} else {
		c.Redirect(http.StatusSeeOther, "/userAccount") // User account page
	}
}

func ValidateToken(c *gin.Context) {
	// Try to get token from Authorization header
	tokenString := c.GetHeader("Authorization")
	if tokenString == "" {
		// If not in header, try to get from cookie
		var err error
		tokenString, err = c.Cookie("auth_token")
		if err != nil || tokenString == "" {
			c.HTML(http.StatusUnauthorized, "login.html", gin.H{
				"Title": "Login",
				"Error": "Please log in to access this page",
			})
			c.Abort()
			return
		}
	} else {
		// Remove 'Bearer ' from the token string if it exists
		if len(tokenString) > 7 && tokenString[:6] == "Bearer " {
			tokenString = tokenString[6:]
		}
	}

	// Parse and validate the token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method %v", token.Header["alg"])
		}
		return JwtSecretKey, nil
	})

	if err != nil || !token.Valid {
		c.HTML(http.StatusUnauthorized, "login.html", gin.H{
			"Title": "Login",
			"Error": "Your session has expired. Please log in again.",
		})
		c.Abort()
		return
	}

	// Extract user data from the token
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		c.HTML(http.StatusUnauthorized, "login.html", gin.H{
			"Title": "Login",
			"Error": "Invalid session. Please log in again.",
		})
		c.Abort()
		return
	}

	// Get role and other user data from claims
	role, ok := claims["role"].(string)
	if !ok {
		c.HTML(http.StatusUnauthorized, "login.html", gin.H{
			"Title": "Login",
			"Error": "Invalid session data. Please log in again.",
		})
		c.Abort()
		return
	}

	// Set user data in the context for use in handlers
	id := int(claims["id"].(float64))
	username := claims["username"].(string)
	email := claims["email"].(string)

	c.Set("user_id", id)
	c.Set("username", username)
	c.Set("email", email)
	c.Set("role", role)

	c.Next()
}

func AdminPage(c *gin.Context) {
	role, ok := c.Get("role")
	if !ok || role != "admin" {
		c.HTML(http.StatusForbidden, "login.html", gin.H{
			"Title": "Login",
			"Error": "You don't have permission to access this page",
		})
		return
	}

	// Get user data from context
	username, _ := c.Get("username")
	email, _ := c.Get("email")

	// Get user count
	var userCount int
	err := DB.QueryRow("SELECT COUNT(*) FROM accounts").Scan(&userCount)
	if err != nil {
		log.Printf("Error getting user count: %v", err)
		userCount = 0
	}

	// Get employee count
	var employeeCount int
	err = DB.QueryRow("SELECT COUNT(*) FROM users").Scan(&employeeCount)
	if err != nil {
		log.Printf("Error getting employee count: %v", err)
		employeeCount = 0
	}

	// Get admin count
	var adminCount int
	err = DB.QueryRow("SELECT COUNT(*) FROM accounts WHERE role = 'admin'").Scan(&adminCount)
	if err != nil {
		log.Printf("Error getting admin count: %v", err)
		adminCount = 0
	}

	// Calculate remaining admin slots
	remainingAdminSlots := 5 - adminCount
	if remainingAdminSlots < 0 {
		remainingAdminSlots = 0
	}

	// Fetch users for the table
	rows, err := DB.Query("SELECT id, username, email, role, created_at FROM accounts LIMIT 10")
	if err != nil {
		log.Printf("Error fetching users: %v", err)
	}
	defer rows.Close()

	type UserData struct {
		ID        int
		Username  string
		Email     string
		Role      string
		CreatedAt string
	}

	var users []UserData
	for rows.Next() {
		var user UserData
		var createdAt time.Time
		err := rows.Scan(&user.ID, &user.Username, &user.Email, &user.Role, &createdAt)
		if err != nil {
			log.Printf("Error scanning user row: %v", err)
			continue
		}
		user.CreatedAt = createdAt.Format("2006-01-02 15:04:05")
		users = append(users, user)
	}

	c.HTML(http.StatusOK, "admin.html", gin.H{
		"Title":               "Admin Panel",
		"Username":            username,
		"Email":               email,
		"UserCount":           userCount,
		"EmployeeCount":       employeeCount,
		"AdminCount":          adminCount,
		"RemainingAdminSlots": remainingAdminSlots,
		"CanCreateAdmin":      remainingAdminSlots > 0,
		"NewToday":            0,
		"Users":               users,
	})
}

func UserPage(c *gin.Context) {
	role, ok := c.Get("role")
	if !ok || role != "user" {
		c.HTML(http.StatusForbidden, "login.html", gin.H{
			"Title": "Login",
			"Error": "You don't have permission to access this page",
		})
		return
	}

	// Get user data from context
	username, _ := c.Get("username")
	email, _ := c.Get("email")

	c.HTML(http.StatusOK, "user.html", gin.H{
		"Title":    "User Dashboard",
		"Username": username,
		"Email":    email,
	})
}
