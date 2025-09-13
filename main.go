package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"

	"github.com/iveteran/OAuth2WebFlow/controller"
	"github.com/iveteran/OAuth2WebFlow/service"

	_ "github.com/mattn/go-sqlite3"
)

func main() {
	db, err := sql.Open("sqlite3", "./oauth2.db")
	if err != nil {
		log.Fatal(err)
	}

	authService := &service.AuthService{DB: db}
	authController := &controller.AuthController{Service: authService}

	authService.InitDB()

	http.HandleFunc("/authorize", authController.Authorize)
	http.HandleFunc("/callback", authController.Callback)
	http.HandleFunc("/get_token", authController.GetToken)

	fmt.Println("Server running at http://localhost:9090")
	log.Fatal(http.ListenAndServe(":9090", nil))
}
