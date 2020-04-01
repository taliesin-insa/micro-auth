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
	"strconv"
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
// CREATE TABLE sessions(id int not null auto_increment, token varchar(256), primary key(id));
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


	selectStatement, selectErr := Db.Prepare("SELECT password FROM users WHERE username = ?")

	if selectErr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Printf("[ERROR] Error while preparing request: %v", selectErr.Error())
		_, err = w.Write([]byte("[MICRO-AUTH] Could not prepare request"))
		return
	}

	defer selectStatement.Close()

	var hash string

	err = selectStatement.QueryRow(reqData.Username).Scan(&hash)
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
			w.Write([]byte("[MICRO-AUTH] Error while generating secret"))
			return
		}

		// inserting Token in session table of database

		insertSessionStatement, insertPrepareErr := Db.Prepare("INSERT INTO sessions VALUES (0, ?)")

		if insertPrepareErr != nil {
			w.WriteHeader(http.StatusInternalServerError)
			log.Printf("[ERROR] Error while preparing INSERT of session data : %v", insertPrepareErr.Error())
			w.Write([]byte("[MICRO-AUTH] Error while writing session data to database"))
			return
		}

		defer insertSessionStatement.Close()

		insertRes, insertExecErr := insertSessionStatement.Exec(tokenString)
		insertedRows, _ := insertRes.RowsAffected()

		if insertExecErr != nil || insertedRows != 1 {
			w.WriteHeader(http.StatusInternalServerError)
			log.Printf("[ERROR] Error while executing INSERT of session data : %v", insertExecErr.Error())
			w.Write([]byte("[MICRO-AUTH] Error while writing session data to database"))
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

		selectStatement, selectErr := Db.Prepare("SELECT count(token) FROM sessions WHERE token = ?")

		if selectErr != nil {
			w.WriteHeader(http.StatusInternalServerError)
			log.Printf("[ERROR] Error while preparing request: %v", selectErr.Error())
			_, err = w.Write([]byte("[MICRO-AUTH] Could not prepare request"))
			return
		}

		defer selectStatement.Close()

		var count string

		sessionQueryErr := selectStatement.QueryRow(reqData.Token).Scan(&count)
		intCount, sessionCountErr := strconv.Atoi(count)

		if sessionCountErr != nil {
			panic("[PANIC] unexpected value received from count(session)")
		}

		if sessionQueryErr != nil {
			log.Printf("[ERROR] Error while querying session table: %v", selectErr.Error())
			_, err = w.Write([]byte("[MICRO-AUTH] Could not query database for session information"))
			return
		}

		if intCount == 1 {
			w.WriteHeader(http.StatusOK)
			m, _ :=json.Marshal(VerifyResponse{Username: claims.Username})
			w.Write(m)
		} else {
			w.WriteHeader(http.StatusUnauthorized)
		}

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
	router.HandleFunc("/auth/", home)
	router.HandleFunc("/auth/login", login).Methods("POST")
	//router.HandleFunc("/logout", logout).Methods("POST")
	router.HandleFunc("/auth/verifyToken", verify).Methods("POST")

	log.Fatal(http.ListenAndServe(":8080", router))
}
