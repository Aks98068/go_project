package main

import (
	"database/sql"
	"fmt"
	Routes "goweb/routes"
	"html/template"
	"log"

	_ "github.com/go-sql-driver/mysql"

	"github.com/gin-gonic/gin"
)

func main() {
	// Database connection setup
	db, err := sql.Open("mysql", "root:@tcp(localhost:3306)/eprotfolio")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close() // Close the database connection when the application exits

	// Ping the database to ensure it's reachable
	err = db.Ping()
	if err != nil {
		log.Fatal("Error pinging the database: ", err)
	}
	fmt.Println("Successfully connected to the database!")

	// Initialize DB for the Routes package
	Routes.InitDB(db)

	// Set up Gin router
	router := gin.Default()

	// Add custom template functions
	router.SetFuncMap(template.FuncMap{
		"subtract": func(a, b int) int {
			return a - b
		},
	})

	// Load templates and static files
	router.LoadHTMLGlob("templates/*")
	router.Static("/static", "./static")

	// Register all routes from the Routes package
	Routes.Routes(router)

	// Set trusted proxies
	router.SetTrustedProxies([]string{"127.0.0.1"}) // Only trust localhost

	// Start the server
	log.Println("Server running on http://localhost:8081")
	router.Run(":8081")
}
