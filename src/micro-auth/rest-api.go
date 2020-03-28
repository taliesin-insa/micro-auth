package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"io/ioutil"
	"log"
	"net/http"
	"os"
)

var Db *sql.DB

type AuthRequest struct {
	Username  string
	Password  string
}

type AuthResponse struct {
	Username  string
	Role int
}

func home(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "you're talking to the auth microservice")
}

// CREATE DATABASE taliesin;
// CREATE DATABASE taliesin_dev;
// CREATE TABLE users(username varchar(100), password varchar(255), role int, primary key(username));
func authenticate(w http.ResponseWriter, r *http.Request) {

	reqBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Fatal(err)
		return
	}

	var reqData AuthRequest
	err = json.Unmarshal(reqBody, &reqData)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		log.Printf("[ERROR] Unmarshal request json failed: %v", err.Error())
		_, err = w.Write([]byte("[MICRO-AUTH] Wrong request body format"))
		return
	}


	statement, err := Db.Prepare("SELECT password FROM users WHERE username = ?")

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Printf("[ERROR] Error while preparing request: %v", err.Error())
		_, err = w.Write([]byte("[MICRO-AUTH] Could not prepare request"))
		return
	}

	defer statement.Close()

	var hash string

	err = statement.QueryRow(reqData.Username).Scan(&hash)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	dbHash := fmt.Sprintf("%x", sha256.Sum256([]byte(reqData.Password)))

	if dbHash == hash {
		w.WriteHeader(http.StatusOK)
		m, _ :=json.Marshal(AuthResponse{Username:reqData.Username})
		w.Write(m)
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
}

func main() {

	var passwordValue string
	var dbName = "taliesin"

	if value, isPasswordPresent := os.LookupEnv("DB_PASSWORD") ; !isPasswordPresent {
		panic("DB_PASSWORD is not present in env, aborting.")
	} else {
		passwordValue = value
	}

	if os.Getenv("MICRO_ENVIRONMENT") != "production" {
		dbName = "taliesin_dev"
	}

	databasePtr, err := sql.Open("mysql", "taliesin:"+passwordValue+"@tcp(10.133.33.51:3306)/"+dbName)
	Db = databasePtr

	if err != nil {
		log.Fatal(err)
	}

	defer Db.Close()

	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/", home)
	router.HandleFunc("/auth", authenticate).Methods("POST")

	log.Fatal(http.ListenAndServe(":8080", router))
}
