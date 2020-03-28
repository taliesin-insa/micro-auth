package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"io/ioutil"
	"log"
	"net/http"
	"os"
)

var Db *sql.DB
var HMACSecret []byte

type AuthRequest struct {
	Username  string
	Password  string
}

type VerifyRequest struct {
	Token  string
}

type JwtClaims struct {
	Username  string
	jwt.StandardClaims
}

type VerifyResponse struct {
	Username  string
}

type AuthResponse struct {
	Username  string
	Token string
}

func home(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "you're talking to the auth microservice")
}

// CREATE DATABASE taliesin;
// CREATE DATABASE taliesin_dev;
// CREATE TABLE users(username varchar(100), password varchar(255), role int, primary key(username));
func login(w http.ResponseWriter, r *http.Request) {

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

	// verify that sha256(provided password) = database hash

	dbHash := fmt.Sprintf("%x", sha256.Sum256([]byte(reqData.Password)))

	if dbHash == hash {
		// generate jwt token
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, JwtClaims{Username: reqData.Username})

		tokenString, signingErr := token.SignedString(HMACSecret)

		if signingErr != nil {
			w.WriteHeader(http.StatusInternalServerError)
			log.Printf("[ERROR] Error while generating JWT: %v", err.Error())
			_, err = w.Write([]byte("[MICRO-AUTH] Error while generating secret"))
			return
		}

		w.WriteHeader(http.StatusOK)
		m, _ :=json.Marshal(AuthResponse{Username:reqData.Username, Token:tokenString})
		w.Write(m)
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
}

func verify(w http.ResponseWriter, r *http.Request) {
	reqBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Fatal(err)
		return
	}

	var reqData VerifyRequest
	unmarshalErr := json.Unmarshal(reqBody, &reqData)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		log.Printf("[ERROR] Unmarshal request json failed: %v", unmarshalErr.Error())
		w.Write([]byte("[MICRO-AUTH] Wrong request body format"))
		return
	}

	// XXX: the same HMAC secret is used for each signing, this may change

	token, verifyErr := jwt.ParseWithClaims(reqData.Token, &JwtClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return HMACSecret, nil
	})

	if verifyErr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Printf("[ERROR] Error while verifying JWT: %v", verifyErr.Error())
		w.Write([]byte("[MICRO-AUTH] Could not verify token (bad input data ?)"))
		return
	}


	if claims, ok := token.Claims.(*JwtClaims); ok && token.Valid {
		w.WriteHeader(http.StatusOK)
		m, _ :=json.Marshal(VerifyResponse{Username: claims.Username})
		w.Write(m)
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
}

func main() {

	var passwordValue string
	var dbName = "taliesin"

	if value, isDbPasswordPresent := os.LookupEnv("DB_PASSWORD") ; !isDbPasswordPresent {
		panic("DB_PASSWORD is not present in env, aborting.")
	} else {
		passwordValue = value
	}

	if value, isHMACSecretPresent := os.LookupEnv("HMAC_SECRET") ; !isHMACSecretPresent {
		panic("HMAC_SECRET is not present in env, aborting.")
	} else {
		HMACSecret = []byte(value)
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
	router.HandleFunc("/login", login).Methods("POST")
	router.HandleFunc("/verifyToken", verify).Methods("POST")

	log.Fatal(http.ListenAndServe(":8080", router))
}
