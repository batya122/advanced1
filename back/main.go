package main

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"html/template"
	"log"
	"net/http"
	"net/smtp"
	"regexp"
)

var db *gorm.DB

func main() {
	// Connect to the database
	dsn := "user=postgres password=1234 dbname=postgres host=localhost port=5432 sslmode=disable"
	var err error
	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("Error connecting to database: %v", err)
	}

	// Auto Migrate the user struct
	err = db.AutoMigrate(&User{})
	if err != nil {
		log.Fatalf("Error migrating database schema: %v", err)
	}

	// Define routes
	http.HandleFunc("/", redirectToLogin)
	http.HandleFunc("/aboutd.html", aboutHandler)
	http.HandleFunc("/adminpanel.html", adminHandler)
	http.HandleFunc("/contact.html", contactHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/registration", registrationHandler)
	http.HandleFunc("/index.html", indexHandler)
	http.HandleFunc("/createuser", createUserHandler)
	http.HandleFunc("/getuser", getUserHandler)
	http.HandleFunc("/updateuser", updateUserHandler)
	http.HandleFunc("/deleteuser", deleteUserHandler)
	http.HandleFunc("/confirm", confirmationHandler)

	// Start the server
	log.Println("Server started on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

type User struct {
	ID                uint   `gorm:"primaryKey;autoIncrement"`
	Username          string `gorm:"unique"`
	Email             string `gorm:"unique"`
	Password          string
	ConfirmationToken string
	Confirmed         bool
}

func redirectToLogin(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	renderTemplate(w, "index.html", nil)
}

func aboutHandler(w http.ResponseWriter, r *http.Request) {
	renderTemplate(w, "aboutd.html", nil)
}

func adminHandler(w http.ResponseWriter, r *http.Request) {
	// Fetch users from the database
	var users []User
	result := db.Find(&users)
	if result.Error != nil {
		http.Error(w, result.Error.Error(), http.StatusInternalServerError)
		log.Printf("Error fetching users from database: %v\n", result.Error)
		return
	}

	// Pass users to the HTML template
	data := struct {
		Users []User
	}{
		Users: users,
	}

	renderTemplate(w, "adminpanel.html", data)
}

func contactHandler(w http.ResponseWriter, r *http.Request) {
	renderTemplate(w, "contact.html", nil)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		// Retrieve form values
		email := r.FormValue("email")
		password := r.FormValue("password")

		// Check if the user exists in the database
		var user User
		result := db.Where("email = ?", email).First(&user)
		if result.Error != nil {
			// If user not found, render the login page again with an error message
			log.Printf("User not found for email: %s\n", email)
			data := struct {
				ErrorMessage string
			}{
				ErrorMessage: "User not found",
			}
			renderTemplate(w, "login.html", data)
			return
		}

		// Check if the password matches
		if user.Password != password {
			// If password doesn't match, render the login page again with an error message
			log.Printf("Incorrect password for email: %s\n", email)
			data := struct {
				ErrorMessage string
			}{
				ErrorMessage: "Incorrect password",
			}
			renderTemplate(w, "login.html", data)
			return
		}

		// Check if the user is admin
		if email == "admin@admin.com" && password == "admin" {
			// Redirect admin to admin panel
			log.Println("Admin logged in, redirecting to admin panel")
			http.Redirect(w, r, "/adminpanel.html", http.StatusSeeOther)
			return
		}

		// Redirect user to main page upon successful login
		log.Println("User logged in, redirecting to main page")
		http.Redirect(w, r, "/index.html", http.StatusSeeOther)
		return
	}

	// If the request is not a POST request, render the login page
	renderTemplate(w, "login.html", nil)
}

func registrationHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		// Retrieve form values
		username := r.FormValue("username")
		email := r.FormValue("email")
		password := r.FormValue("password")

		// Check if username already exists
		var existingUser User
		result := db.Where("username = ?", username).First(&existingUser)
		if result.Error != nil {
			if !errors.Is(result.Error, gorm.ErrRecordNotFound) {
				// Error occurred while querying the database, handle the error
				http.Error(w, result.Error.Error(), http.StatusInternalServerError)
				return
			}
		} else {
			// Username already exists, handle the error
			// For example, render the registration page again with an error message
			data := struct {
				ErrorMessage string
			}{
				ErrorMessage: "Username already exists",
			}
			renderTemplate(w, "registration.html", data)
			return
		}

		// Generate confirmation token
		confirmationToken := generateToken()

		// Perform registration by inserting the new user into the database
		newUser := User{Username: username, Email: email, Password: password, ConfirmationToken: confirmationToken}
		result = db.Create(&newUser)
		if result.Error != nil {
			// Error occurred while creating user, handle the error
			http.Error(w, result.Error.Error(), http.StatusInternalServerError)
			return
		}

		// Send confirmation email
		err := sendConfirmationEmail(email, confirmationToken)
		if err != nil {
			// Error occurred while sending confirmation email, handle the error
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Redirect user to main page upon successful registration
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	// If the request is not a POST request, render the registration page
	renderTemplate(w, "registration.html", nil)
}

func confirmationHandler(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")

	// Retrieve user by confirmation token
	var user User
	result := db.Where("confirmation_token = ?", token).First(&user)
	if result.Error != nil {
		// Handle invalid or expired token
		// Redirect to an error page or display an error message
		http.Error(w, "Invalid or expired token", http.StatusBadRequest)
		return
	}

	// Activate user account
	user.Confirmed = true
	user.ConfirmationToken = ""
	db.Save(&user)

	// Redirect to a success page or display a success message
	http.Redirect(w, r, "/confirmation/success", http.StatusSeeOther)
}

func generateToken() string {
	token := make([]byte, 32)
	_, err := rand.Read(token)
	if err != nil {
		panic(err) // You may want to handle this error more gracefully
	}
	return base64.URLEncoding.EncodeToString(token)
}

func sendConfirmationEmail(email, token string) error {
	// SMTP configuration
	smtpHost := "smtp.gmail.com"
	smtpPort := "465"
	smtpUsername := "jukabaevb@gmail.com"
	smtpPassword := "kpvn uicb cngr zpjr" // Update with your actual password

	auth := smtp.PlainAuth("", smtpUsername, smtpPassword, smtpHost)

	// Email content
	to := []string{email}
	subject := "Confirm your registration"
	body := "Please click the following link to confirm your registration: http://localhost:8080/confirm?token=" + token

	// Construct email message
	msg := []byte("To: " + email + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"\r\n" +
		body + "\r\n")

	// Send email
	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, smtpUsername, to, msg)
	if err != nil {
		log.Printf("Error sending confirmation email to %s: %v\n", email, err)
		return err
	}
	log.Printf("Confirmation email sent to %s\n", email)
	return nil
}

func createUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		// Retrieve data of the new user from the request
		email := r.FormValue("email")
		username := r.FormValue("username")
		password := r.FormValue("password")

		// Check if all required fields are present
		if email == "" || username == "" || password == "" {
			http.Error(w, "All fields are required", http.StatusBadRequest)
			return
		}

		// Check if a user with the same email already exists
		var existingUser User
		result := db.Where("email = ?", email).First(&existingUser)
		if result.Error == nil {
			http.Error(w, "User with this email already exists", http.StatusBadRequest)
			return
		}

		// Generate confirmation token
		confirmationToken := generateToken()

		// Perform registration by inserting the new user into the database
		newUser := User{Username: username, Email: email, Password: password, ConfirmationToken: confirmationToken}
		result = db.Create(&newUser)
		if result.Error != nil {
			http.Error(w, result.Error.Error(), http.StatusInternalServerError)
			return
		}

		// Send confirmation email
		err := sendConfirmationEmail(email, confirmationToken)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Send a success response
		w.WriteHeader(http.StatusCreated)
		return
	}

	// If the request method is not POST, return an error
	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func getUserHandler(w http.ResponseWriter, r *http.Request) {
	// Получаем ID пользователя из URL-адреса или из запроса
	userID := r.FormValue("id")

	// Проверяем, что ID пользователя не является пустым
	if userID == "" {
		http.Error(w, "User ID is required", http.StatusBadRequest)
		return
	}

	// Парсим ID пользователя в uint
	var userIDUint uint
	_, err := fmt.Sscanf(userID, "%d", &userIDUint)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	// Ищем пользователя в базе данных по его ID
	var user User
	result := db.First(&user, userIDUint)
	if result.Error != nil {
		http.Error(w, result.Error.Error(), http.StatusInternalServerError)
		return
	}

	// Передаем данные пользователя в HTML-шаблон
	renderTemplate(w, "user.html", user)
}
func updateUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		userID := r.FormValue("id")

		if userID == "" {
			http.Error(w, "User ID is required", http.StatusBadRequest)
			return
		}

		var userIDUint uint
		_, err := fmt.Sscanf(userID, "%d", &userIDUint)
		if err != nil {
			http.Error(w, "Invalid user ID", http.StatusBadRequest)
			return
		}

		var user User
		result := db.First(&user, userIDUint)
		if result.Error != nil {
			http.Error(w, result.Error.Error(), http.StatusInternalServerError)
			return
		}

		newUsername := r.FormValue("username")
		newEmail := r.FormValue("email")
		newPassword := r.FormValue("password")

		// Обновление данных пользователя только если они не пустые
		if newUsername != "" {
			user.Username = newUsername
		}
		if newEmail != "" {
			user.Email = newEmail
		}
		if newPassword != "" {
			user.Password = newPassword
		}

		result = db.Save(&user)
		if result.Error != nil {
			http.Error(w, result.Error.Error(), http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/adminpanel.html", http.StatusSeeOther)
		return
	}
	renderTemplate(w, "updateuser.html", nil)
}

func deleteUserHandler(w http.ResponseWriter, r *http.Request) {
	// Получаем ID пользователя из URL-адреса или из запроса
	userID := r.FormValue("id")

	// Проверяем, что ID пользователя не является пустым
	if userID == "" {
		http.Error(w, "User ID is required", http.StatusBadRequest)
		return
	}

	// Парсим ID пользователя в uint
	var userIDUint uint
	_, err := fmt.Sscanf(userID, "%d", &userIDUint)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	// Ищем пользователя в базе данных по его ID
	var user User
	result := db.First(&user, userIDUint)
	if result.Error != nil {
		http.Error(w, result.Error.Error(), http.StatusInternalServerError)
		return
	}

	// Удаляем пользователя из базы данных
	result = db.Delete(&user, userIDUint)
	if result.Error != nil {
		http.Error(w, result.Error.Error(), http.StatusInternalServerError)
		return
	}

	// Редиректим на страницу администратора или куда-либо еще
	http.Redirect(w, r, "/adminpanel.html", http.StatusSeeOther)
}

func isStrongPassword(password string) bool {
	// Password must contain at least one uppercase letter, one lowercase letter,
	// one digit, and one special character, and be at least 8 characters long
	// Using regular expressions for validation
	regex := regexp.MustCompile(`^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$`)
	return regex.MatchString(password)
}

func renderTemplate(w http.ResponseWriter, tmpl string, data interface{}) {
	t, err := template.ParseFiles("C:/Users/User/Desktop/Новая папка/advfinal/front/" + tmpl)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Printf("Error rendering template %s: %v\n", tmpl, err)
		return
	}
	err = t.Execute(w, data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Printf("Error executing template %s: %v\n", tmpl, err)
	}
}
