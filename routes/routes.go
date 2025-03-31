package Routes

import (
	"database/sql"
	Signups "goweb/signups"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

var DB *sql.DB

// Initialize DB connection
func InitDB(database *sql.DB) {
	DB = database
	Signups.InitDB(database)
}

func Routes(router *gin.Engine) {
	// Public routes - no authentication required

	// Main landing page
	router.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", gin.H{
			"Title": "Main website",
		})
	})

	// Home route (alternative to /)
	router.GET("/home", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", gin.H{
			"Title": "Main website",
		})
	})

	// Static info pages
	router.GET("/bootstrap", func(c *gin.Context) {
		c.HTML(http.StatusOK, "bootstrap.html", gin.H{
			"Title": "bootstrap",
		})
	})

	router.GET("/css", func(c *gin.Context) {
		c.HTML(http.StatusOK, "css.html", gin.H{
			"Title": "css",
		})
	})

	router.GET("/javascript", func(c *gin.Context) {
		c.HTML(http.StatusOK, "javascript.html", gin.H{
			"Title": "javascript",
		})
	})

	router.GET("/html", func(c *gin.Context) {
		c.HTML(http.StatusOK, "html.html", gin.H{
			"Title": "html",
		})
	})

	router.GET("/fullstack", func(c *gin.Context) {
		c.HTML(http.StatusOK, "fullstack.html", gin.H{
			"Title": "images",
		})
	})

	// Authentication related routes
	router.GET("/login", func(c *gin.Context) {
		c.HTML(http.StatusOK, "login.html", gin.H{
			"Title": "Login",
		})
	})

	router.GET("/signup", func(c *gin.Context) {
		c.HTML(http.StatusOK, "signup.html", gin.H{
			"Title": "Sign Up",
		})
	})

	router.POST("/signups", Signups.Signup)
	router.POST("/logins", Signups.Login)

	// Logout route
	router.GET("/logout", func(c *gin.Context) {
		// Clear the auth cookie
		c.SetCookie("auth_token", "", -1, "/", "", false, true)
		// Redirect to login page
		c.Redirect(http.StatusSeeOther, "/login")
	})

	// Protected routes that need authentication
	authorized := router.Group("/")
	authorized.Use(Signups.ValidateToken)
	{
		authorized.GET("/adminAccount", Signups.AdminPage)
		authorized.GET("/userAccount", Signups.UserPage)

		// Employee management routes
		authorized.GET("/usermanagement", func(c *gin.Context) {
			if DB == nil {
				log.Println("Database connection is not initialized")
				c.HTML(http.StatusInternalServerError, "login.html", gin.H{
					"Title": "Login",
					"Error": "Server error. Please try again later.",
				})
				return
			}

			data, errr := DB.Query("SELECT * FROM users")
			if errr != nil {
				log.Printf("Error querying database: %v", errr)
				c.HTML(http.StatusInternalServerError, "users.html", gin.H{
					"Title": "Users",
					"Error": "Failed to fetch users from database",
				})
				return
			}
			defer data.Close()

			type Employee struct {
				ID          int
				Name        string
				Email       string
				Phonenumber string
			}

			var employees []Employee

			for data.Next() {
				var emp Employee
				err := data.Scan(&emp.ID, &emp.Name, &emp.Email, &emp.Phonenumber)
				if err != nil {
					log.Printf("Error scanning row: %v", err)
					continue
				}
				log.Printf("Found employee: ID=%d, Name=%s, Email=%s, Phone=%s", emp.ID, emp.Name, emp.Email, emp.Phonenumber)
				employees = append(employees, emp)
			}

			log.Printf("Total employees found: %d", len(employees))

			// Check if we have any employees
			if len(employees) == 0 {
				log.Println("No employees found in the database")
			}

			// Pass the data to the template
			c.HTML(http.StatusOK, "usermanagement.html", gin.H{
				"Title": "Users",
				"Users": employees,
			})
		})

		authorized.POST("/adduser", func(c *gin.Context) {
			if DB == nil {
				log.Println("Database connection is not initialized")
				c.HTML(http.StatusInternalServerError, "login.html", gin.H{
					"Title": "Login",
					"Error": "Server error. Please try again later.",
				})
				return
			}

			name := c.PostForm("name")
			email := c.PostForm("email")
			phonenumber := c.PostForm("phonenumber")

			// First validate the input
			if name == "" || email == "" || phonenumber == "" {
				c.HTML(http.StatusBadRequest, "users.html", gin.H{
					"Title": "Employee Data",
					"Error": "All fields are required",
				})
				return
			}

			// Then insert data into database
			_, err := DB.Exec("INSERT INTO users (name, email, phonenumber) VALUES (?, ?, ?)", name, email, phonenumber)
			if err != nil {
				log.Printf("Error inserting user: %v", err)
				c.HTML(http.StatusInternalServerError, "users.html", gin.H{
					"Title": "Employee Data",
					"Error": "Failed to add user to database",
				})
				return
			}

			log.Printf("Successfully added new user: %s", name)
			// redirect to users page
			c.Redirect(http.StatusSeeOther, "/usermanagement")
		})

		// Admin-only routes
		adminOnly := authorized.Group("/admin")
		adminOnly.Use(adminRoleCheckMiddleware)
		{
			adminOnly.GET("/create-admin", createAdminFormHandler)
			adminOnly.POST("/create-admin", createAdminHandler)
		}
	}
}

// Middleware to check if the user has admin role
func adminRoleCheckMiddleware(c *gin.Context) {
	role, exists := c.Get("role")
	if !exists || role != "admin" {
		c.HTML(http.StatusForbidden, "login.html", gin.H{
			"Title": "Access Denied",
			"Error": "You don't have permission to access this page",
		})
		c.Abort()
		return
	}
	c.Next()
}

// Handler for the admin creation form
func createAdminFormHandler(c *gin.Context) {
	// Get admin count
	var adminCount int
	err := DB.QueryRow("SELECT COUNT(*) FROM accounts WHERE role = 'admin'").Scan(&adminCount)
	if err != nil {
		log.Printf("Error getting admin count: %v", err)
		adminCount = 0
	}

	// Calculate remaining admin slots
	remainingAdminSlots := 5 - adminCount
	if remainingAdminSlots < 0 {
		remainingAdminSlots = 0
	}

	// Render form
	c.HTML(http.StatusOK, "create_admin.html", gin.H{
		"Title":               "Create Admin Account",
		"RemainingAdminSlots": remainingAdminSlots,
		"CanCreateAdmin":      remainingAdminSlots > 0,
	})
}

// Handler for the admin creation POST
func createAdminHandler(c *gin.Context) {
	// Force the role to be admin for this handler
	c.Request.PostForm.Set("role", "admin")

	// Call the standard signup function
	Signups.Signup(c)
}
