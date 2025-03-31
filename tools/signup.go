package Signups

import (
	"database/sql"
	"net/http"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

var DB *sql.DB

func hashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

func Signup(c *gin.Context) {
	Name := c.PostForm("name")
	Email := c.PostForm("email")
	Password := c.PostForm("password")
	Role := c.PostForm("role")

	HashedPassword, err := hashPassword(Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	_, err = DB.Exec("INSERT INTO accounts(name, email, password, role) VALUES(?,?,?,?)", Name, Email, HashedPassword, Role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to insert data"})
		return
	}

	c.Redirect(http.StatusSeeOther, "/login")

}
