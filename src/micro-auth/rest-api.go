package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"
)

var Db *sql.DB
var HMACSecret []byte

var (
	httpRequestsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "http_requests_total",
		Help: "Number of HTTP requests processed by the microservice",
	})

	authentifiedUsersTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "auth_users_total",
		Help: "Number of users with a session currently opened",
	})

)

const (
	RoleAdmin = iota
	RoleAnnotator = iota
)

type AccountData struct {
	Username	string
	Email		string
	Role		int
}

func (r AccountData) isValid() bool {
	return r.Username != "" && r.Email != "" && r.Role >= 0 && r.Role <= 1
}


type AuthRequest struct {
	Username  string
	Password  string
}

func (r AuthRequest) isValid() bool {
	return r.Username != "" && r.Password != ""
}

type VerifyRequest struct {
	Token  string
}

func (r VerifyRequest) isValid() bool {
	return r.Token != ""
}


type AccountCreationRequest struct {
	AdminToken 	string
	Username	string
	Email		string
	Role		int
	Password 	string
}

func (r AccountCreationRequest) isValid() bool {
	return r.AdminToken != "" && r.Username != "" && r.Email != "" && r.Role >= 0 && r.Role <= 1 && r.Password != ""
}


type AccountModifyRequest struct {
	AdminToken 	string
	Username	string
	Email		string
	Role		int
}

func (r AccountModifyRequest) isValid() bool {
	return r.AdminToken != "" && r.Username != "" && r.Email != "" && r.Role >= 0 && r.Role <= 1
}


type PasswordModifyRequest struct {
	Username  string
	OldPassword  string
	NewPassword  string
}

func (r PasswordModifyRequest) isValid() bool {
	return r.Username != "" && r.NewPassword != "" && r.OldPassword != ""
}


type AccountDeletionRequest struct {
	Username   string
	AdminToken string
}

func (r AccountDeletionRequest) isValid() bool {
	return r.AdminToken != "" && r.Username != ""
}


type JwtClaims struct {
	Username	string
	Email 		string
	Role		int
	jwt.StandardClaims
}

type AuthResponse struct {
	Username	string
	Email 		string
	Role		int
	Token		string
}


func home(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "you're talking to the auth microservice")
}

// CREATE DATABASE taliesin;
// CREATE DATABASE taliesin_dev;
// CREATE TABLE users(username varchar(100), password varchar(255), role int, email varchar(255), primary key(username));
// CREATE TABLE sessions(id int not null auto_increment, token varchar(256), primary key(id));
func login(w http.ResponseWriter, r *http.Request) {

	httpRequestsTotal.Inc()

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

	if !reqData.isValid() {
		w.WriteHeader(http.StatusBadRequest)
		_, err = w.Write([]byte("[MICRO-AUTH] Wrong request body format, validation failed"))
		return
	}

	selectStatement, selectErr := Db.Prepare("SELECT email, password, role FROM users WHERE username = ?")

	if selectErr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Printf("[ERROR] Error while preparing request: %v", selectErr.Error())
		_, err = w.Write([]byte("[MICRO-AUTH] Could not prepare request"))
		return
	}

	defer selectStatement.Close()

	var hash string
	var role int
	var email string

	err = selectStatement.QueryRow(reqData.Username).Scan(&email, &hash, &role)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		log.Printf("%v", err)
		return
	}

	// verify that sha256(provided password) = database hash

	dbHash := fmt.Sprintf("%x", sha256.Sum256([]byte(reqData.Password)))

	if dbHash == hash {
		// generate jwt token
		stdclaims := jwt.StandardClaims{
			IssuedAt: time.Now().Unix(),
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, JwtClaims{
			Username: reqData.Username,
			Role: role,
			Email: email,
			StandardClaims: stdclaims,
		})

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

		authentifiedUsersTotal.Inc()

		w.WriteHeader(http.StatusOK)
		m, _ :=json.Marshal(AuthResponse{Username:reqData.Username, Email: email, Role: role, Token:tokenString})
		w.Write(m)
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
}

func checkToken(tokenString string) (*JwtClaims, error, int) {
	// XXX: the same HMAC secret is used for each signing, this may change

	token, verifyErr := jwt.ParseWithClaims(tokenString, &JwtClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return HMACSecret, nil
	})

	if verifyErr != nil {
		log.Printf("[ERROR] Error while verifying JWT: %v", verifyErr.Error())
		return nil, errors.New("[MICRO-AUTH] Could not verify token (bad input data ?)"), http.StatusBadRequest
	}


	if claims, ok := token.Claims.(*JwtClaims); ok && token.Valid {

		selectStatement, selectErr := Db.Prepare("SELECT count(token) FROM sessions WHERE token = ?")

		if selectErr != nil {
			log.Printf("[ERROR] Error while preparing select request (checkToken): %v", selectErr.Error())
			return nil, errors.New("[MICRO-AUTH] Could not prepare request"), http.StatusInternalServerError
		}

		defer selectStatement.Close()

		var count string

		sessionQueryErr := selectStatement.QueryRow(tokenString).Scan(&count)
		intCount, sessionCountErr := strconv.Atoi(count)

		if sessionCountErr != nil {
			panic("[PANIC] unexpected value received from count(session)")
		}

		if sessionQueryErr != nil {
			log.Printf("[ERROR] Error while querying session table: %v", selectErr.Error())
			return nil, errors.New("[MICRO-AUTH] Could not query database for session information"), http.StatusInternalServerError
		}

		if intCount == 1 {
			return claims, nil, http.StatusOK
		} else {
			return nil, errors.New("[MICRO-AUTH] Session invalid/expired"), http.StatusUnauthorized
		}

	} else {
		return nil, nil, http.StatusUnauthorized
	}

}

func verify(w http.ResponseWriter, r *http.Request) {
	httpRequestsTotal.Inc()

	reqBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Fatal(err)
		return
	}

	var reqData VerifyRequest
	unmarshalErr := json.Unmarshal(reqBody, &reqData)
	if unmarshalErr != nil {
		w.WriteHeader(http.StatusBadRequest)
		log.Printf("[ERROR] Unmarshal request json failed: %v", unmarshalErr.Error())
		w.Write([]byte("[MICRO-AUTH] Wrong request body format"))
		return
	}

	if !reqData.isValid() {
		w.WriteHeader(http.StatusBadRequest)
		_, err = w.Write([]byte("[MICRO-AUTH] Wrong request body format, validation failed"))
		return
	}

	claims, checkingErr, statusCode := checkToken(reqData.Token)

	if checkingErr != nil {
		w.WriteHeader(statusCode)
		w.Write([]byte(checkingErr.Error()))
		return
	}

	m, _ :=json.Marshal(AccountData{Username: claims.Username, Email: claims.Email, Role: claims.Role})

	w.WriteHeader(http.StatusOK)
	w.Write(m)

}

func checkIfAccountExist(username string, email string) (error, int) {
	selectStatement, selectErr := Db.Prepare("SELECT count(username) FROM users WHERE username = ? OR email = ?")

	if selectErr != nil {
		log.Printf("[ERROR] Error while preparing select request (checkIfAccountExist): %v", selectErr.Error())
		return errors.New("[MICRO-AUTH] Could not prepare request"), http.StatusInternalServerError
	}

	defer selectStatement.Close()

	var count string

	sessionQueryErr := selectStatement.QueryRow(username, email).Scan(&count)
	intCount, sessionCountErr := strconv.Atoi(count)

	if sessionCountErr != nil {
		panic("[PANIC] unexpected value received from checkIfAccountExist")
	}

	if sessionQueryErr != nil {
		log.Printf("[ERROR] Error while querying session users: %v", sessionQueryErr.Error())
		return errors.New("[MICRO-AUTH] Could not query database (checkIfAccountExist)"), http.StatusInternalServerError
	}

	if intCount == 0 {
		return nil, http.StatusOK
	} else {
		return errors.New("[MICRO-AUTH] Username or email already exists"), http.StatusUnauthorized
	}

}

func checkIfEmailExist(username string, email string) (error, int) {
	selectStatement, selectErr := Db.Prepare("SELECT count(username) FROM users WHERE username != ? AND email = ?")

	if selectErr != nil {
		log.Printf("[ERROR] Error while preparing select request (checkIfEmailExist): %v", selectErr.Error())
		return errors.New("[MICRO-AUTH] Could not prepare request"), http.StatusInternalServerError
	}

	defer selectStatement.Close()

	var count string

	sessionQueryErr := selectStatement.QueryRow(username, email).Scan(&count)
	intCount, sessionCountErr := strconv.Atoi(count)

	if sessionCountErr != nil {
		panic("[PANIC] unexpected value received from checkIfEmailExist")
	}

	if sessionQueryErr != nil {
		log.Printf("[ERROR] Error while querying session users: %v", sessionQueryErr.Error())
		return errors.New("[MICRO-AUTH] Could not query database (checkIfEmailExist)"), http.StatusInternalServerError
	}

	if intCount == 0 {
		return nil, http.StatusOK
	} else {
		return errors.New("[MICRO-AUTH] Email already exists"), http.StatusUnauthorized
	}

}



func createAccount(w http.ResponseWriter, r *http.Request) {
	httpRequestsTotal.Inc()

	reqBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Fatal(err)
		return
	}

	var reqData AccountCreationRequest
	unmarshalErr := json.Unmarshal(reqBody, &reqData)
	if unmarshalErr != nil {
		w.WriteHeader(http.StatusBadRequest)
		log.Printf("[ERROR] Unmarshal request json failed: %v", unmarshalErr.Error())
		w.Write([]byte("[MICRO-AUTH] Wrong request body format"))
		return
	}

	if !reqData.isValid() {
		w.WriteHeader(http.StatusBadRequest)
		_, err = w.Write([]byte("[MICRO-AUTH] Wrong request body format, validation failed"))
		return
	}

	existErr, existStatusCode := checkIfAccountExist(reqData.Username, reqData.Email)

	if existErr != nil {
		w.WriteHeader(existStatusCode)
		w.Write([]byte(existErr.Error()))
		return
	}

	claims, checkingErr, statusCode := checkToken(reqData.AdminToken)

	if checkingErr != nil {
		w.WriteHeader(statusCode)
		w.Write([]byte(checkingErr.Error()))
		return
	}

	if claims.Role != RoleAdmin { // Creator needs to be administrator
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("[MICRO-AUTH] Insufficient permissions to create an account"))
		return
	}

	insertSessionStatement, insertPrepareErr := Db.Prepare("INSERT INTO users VALUES (?,?,?,?)")

	if insertPrepareErr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Printf("[ERROR] Error while preparing INSERT of user data : %v", insertPrepareErr.Error())
		w.Write([]byte("[MICRO-AUTH] Error while writing new user data to database"))
		return
	}

	defer insertSessionStatement.Close()

	hashedPassword := fmt.Sprintf("%x", sha256.Sum256([]byte(reqData.Password)))
	insertRes, insertExecErr := insertSessionStatement.Exec(reqData.Username, hashedPassword, reqData.Role, reqData.Email)
	insertedRows, _ := insertRes.RowsAffected()

	if insertExecErr != nil || insertedRows != 1 {
		w.WriteHeader(http.StatusInternalServerError)
		log.Printf("[ERROR] Error while executing INSERT of user data : %v", insertExecErr.Error())
		w.Write([]byte("[MICRO-AUTH] Error while writing new user data to database"))
		return
	}

	m, _ :=json.Marshal(AccountData{Username: reqData.Username, Email: reqData.Email, Role: reqData.Role})

	w.WriteHeader(http.StatusOK)
	w.Write(m)
}

func modifyAccount(w http.ResponseWriter, r *http.Request) {
	httpRequestsTotal.Inc()

	reqBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Fatal(err)
		return
	}

	var reqData AccountModifyRequest
	unmarshalErr := json.Unmarshal(reqBody, &reqData)
	if unmarshalErr != nil {
		w.WriteHeader(http.StatusBadRequest)
		log.Printf("[ERROR] Unmarshal request json failed: %v", unmarshalErr.Error())
		w.Write([]byte("[MICRO-AUTH] Wrong request body format"))
		return
	}

	if !reqData.isValid() {
		w.WriteHeader(http.StatusBadRequest)
		_, err = w.Write([]byte("[MICRO-AUTH] Wrong request body format, validation failed"))
		return
	}

	existErr, existStatusCode := checkIfEmailExist(reqData.Username, reqData.Email)

	if existErr != nil {
		w.WriteHeader(existStatusCode)
		w.Write([]byte(existErr.Error()))
		return
	}

	claims, checkingErr, statusCode := checkToken(reqData.AdminToken)

	if checkingErr != nil {
		w.WriteHeader(statusCode)
		w.Write([]byte(checkingErr.Error()))
		return
	}

	if claims.Role != RoleAdmin { // Modification needs to be made by an administrator
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("[MICRO-AUTH] Insufficient permissions to modify an account"))
		return
	}

	modifyUserStatement, modifyErr := Db.Prepare("UPDATE users SET role = ?, email = ? WHERE username = ?")

	if modifyErr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Printf("[ERROR] Error while preparing UPDATE of user data : %v", modifyErr.Error())
		w.Write([]byte("[MICRO-AUTH] Error while modifying user data on database"))
		return
	}

	defer modifyUserStatement.Close()

	_, modifyExecErr := modifyUserStatement.Exec(reqData.Role, reqData.Email, reqData.Username)

	if modifyExecErr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Printf("[ERROR] Error while executing INSERT of user data : %v", modifyExecErr.Error())
		w.Write([]byte("[MICRO-AUTH] Error while modifying user data on database"))
		return
	}

	m, _ :=json.Marshal(AccountData{Username: reqData.Username, Email: reqData.Email, Role: reqData.Role})

	w.WriteHeader(http.StatusOK)
	w.Write(m)
}

func modifyPassword(w http.ResponseWriter, r *http.Request) {
	httpRequestsTotal.Inc()

	reqBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Fatal(err)
		return
	}

	var reqData PasswordModifyRequest
	unmarshalErr := json.Unmarshal(reqBody, &reqData)
	if unmarshalErr != nil {
		w.WriteHeader(http.StatusBadRequest)
		log.Printf("[ERROR] Unmarshal request json failed: %v", unmarshalErr.Error())
		w.Write([]byte("[MICRO-AUTH] Wrong request body format"))
		return
	}

	if !reqData.isValid() {
		w.WriteHeader(http.StatusBadRequest)
		_, err = w.Write([]byte("[MICRO-AUTH] Wrong request body format, validation failed"))
		return
	}

	// No token verification is done here because we check directly the password

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
		log.Printf("%v", err)
		return
	}

	// verify that sha256(provided password) = database hash

	dbHash := fmt.Sprintf("%x", sha256.Sum256([]byte(reqData.OldPassword)))

	if dbHash == hash {

		modifyUserStatement, modifyErr := Db.Prepare("UPDATE users SET password = ? WHERE username = ?")

		if modifyErr != nil {
			w.WriteHeader(http.StatusInternalServerError)
			log.Printf("[ERROR] Error while preparing UPDATE of user password : %v", modifyErr.Error())
			w.Write([]byte("[MICRO-AUTH] Error while modifying user password on database"))
			return
		}

		defer modifyUserStatement.Close()

		newDbHash := fmt.Sprintf("%x", sha256.Sum256([]byte(reqData.NewPassword)))
		_, modifyExecErr := modifyUserStatement.Exec(newDbHash, reqData.Username)

		if modifyExecErr != nil {
			w.WriteHeader(http.StatusInternalServerError)
			log.Printf("[ERROR] Error while executing UPDATE of user password : %v", modifyExecErr.Error())
			w.Write([]byte("[MICRO-AUTH] Error while modifying user password on database"))
			return
		}

		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
}

func listAccounts(w http.ResponseWriter, r *http.Request) {
	httpRequestsTotal.Inc()

	reqBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Fatal(err)
		return
	}

	var reqData VerifyRequest
	unmarshalErr := json.Unmarshal(reqBody, &reqData)
	if unmarshalErr != nil {
		w.WriteHeader(http.StatusBadRequest)
		log.Printf("[ERROR] Unmarshal request json failed: %v", unmarshalErr.Error())
		w.Write([]byte("[MICRO-AUTH] Wrong request body format"))
		return
	}

	if !reqData.isValid() {
		w.WriteHeader(http.StatusBadRequest)
		_, err = w.Write([]byte("[MICRO-AUTH] Wrong request body format, validation failed"))
		return
	}

	claims, checkingErr, statusCode := checkToken(reqData.Token)

	if checkingErr != nil {
		w.WriteHeader(statusCode)
		w.Write([]byte(checkingErr.Error()))
		return
	}

	if claims.Role != RoleAdmin { // Creator needs to be administrator
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("[MICRO-AUTH] Insufficient permissions to list accounts"))
		return
	}

	selectStatement, selectErr := Db.Prepare("SELECT username, email, role FROM users")

	if selectErr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Printf("[ERROR] Error while preparing select request (listAccounts): %v", selectErr.Error())
		w.Write([]byte("[MICRO-AUTH] Could not prepare request"))
		return
	}

	defer selectStatement.Close()

	rows, queryErr := selectStatement.Query()

	if queryErr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Printf("[ERROR] Error while executing select request (listAccounts): %v", queryErr.Error())
		w.Write([]byte("[MICRO-AUTH] Could not executing request"))
		return
	}

	accounts := make([]AccountData, 0)

	for rows.Next() {

		var username string
		var email string
		var role int

		if err := rows.Scan(&username, &email, &role); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			log.Printf("[ERROR] Error while scanning row (listAccounts): %v", queryErr.Error())
			w.Write([]byte("[MICRO-AUTH] Could not read database"))
			return
		}

		accounts = append(accounts, AccountData{
			Username: username,
			Email: email,
			Role:     role,
		})

	}

	m, _ :=json.Marshal(accounts)

	w.WriteHeader(http.StatusOK)
	w.Write(m)
}

func deleteAccount(w http.ResponseWriter, r *http.Request) {
	httpRequestsTotal.Inc()

	reqBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Fatal(err)
		return
	}

	var reqData AccountDeletionRequest
	unmarshalErr := json.Unmarshal(reqBody, &reqData)
	if unmarshalErr != nil {
		w.WriteHeader(http.StatusBadRequest)
		log.Printf("[ERROR] Unmarshal request json failed: %v", unmarshalErr.Error())
		w.Write([]byte("[MICRO-AUTH] Wrong request body format"))
		return
	}

	if !reqData.isValid() {
		w.WriteHeader(http.StatusBadRequest)
		_, err = w.Write([]byte("[MICRO-AUTH] Wrong request body format, validation failed"))
		return
	}

	claims, checkingErr, statusCode := checkToken(reqData.AdminToken)

	if checkingErr != nil {
		w.WriteHeader(statusCode)
		w.Write([]byte(checkingErr.Error()))
		return
	}

	if claims.Role != RoleAdmin { // Creator needs to be administrator
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("[MICRO-AUTH] Insufficient permissions to delete an account"))
		return
	}

	deleteStatement, deleteErr := Db.Exec("DELETE FROM users WHERE username = ?", reqData.Username)

	if deleteErr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Printf("[ERROR] Error while executing delete (deleteAccount) : %v", deleteErr.Error())
		w.Write([]byte("[MICRO-AUTH] Error while deleting user from database"))
		return
	}

	count, rowsAffectedErr := deleteStatement.RowsAffected()

	if rowsAffectedErr != nil {
		panic("[PANIC] Error while querying rows affected by delete request (logout)")
	}

	if count == 1 {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusBadRequest)
		log.Printf("[ERROR] Rows Affected by delete user statement different from 1, count = %v", count)
		w.Write([]byte("[MICRO-AUTH] User identifier does not exist"))
		return
	}

}


func logout(w http.ResponseWriter, r *http.Request) {
	httpRequestsTotal.Inc()

	reqBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Fatal(err)
		return
	}

	var reqData VerifyRequest
	unmarshalErr := json.Unmarshal(reqBody, &reqData)
	if unmarshalErr != nil {
		w.WriteHeader(http.StatusBadRequest)
		log.Printf("[ERROR] Unmarshal request json failed: %v", unmarshalErr.Error())
		w.Write([]byte("[MICRO-AUTH] Wrong request body format"))
		return
	}

	if !reqData.isValid() {
		w.WriteHeader(http.StatusBadRequest)
		_, err = w.Write([]byte("[MICRO-AUTH] Wrong request body format, validation failed"))
		return
	}

	_, checkingErr, statusCode := checkToken(reqData.Token)

	if checkingErr != nil {
		w.WriteHeader(statusCode)
		w.Write([]byte(checkingErr.Error()))
		return
	}

	deleteStatement, deleteErr := Db.Exec("DELETE FROM sessions WHERE token = ?", reqData.Token)

	if deleteErr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Printf("[ERROR] Error while executing delete (logout) : %v", deleteErr.Error())
		w.Write([]byte("[MICRO-AUTH] Could not delete token from database"))
		return
	}

	count, rowsAffectedErr := deleteStatement.RowsAffected()

	if rowsAffectedErr != nil {
		panic("[PANIC] Error while querying rows affected by delete request (logout)")
	}

	if count == 1 {
		authentifiedUsersTotal.Desc()
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusInternalServerError)
		log.Printf("[ERROR] Rows Affected by delete token statement different from 1")
		w.Write([]byte("[MICRO-AUTH] Could not delete token from database"))
		return
	}


}

func main() {

	var hostValue string
	var portValue string
	var passwordValue string
	var dbName = "taliesin"

	if value, isDbHostPresent := os.LookupEnv("DB_HOST") ; !isDbHostPresent {
		panic("DB_HOST is not present in env, aborting.")
	} else {
		hostValue = value
	}

	if value, isDbPortPresent := os.LookupEnv("DB_PORT") ; !isDbPortPresent {
		panic("DB_PORT is not present in env, aborting.")
	} else {
		portValue = value
	}

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

	databasePtr, err := sql.Open("mysql", "taliesin:"+passwordValue+"@tcp("+hostValue+":"+portValue+")/"+dbName)
	Db = databasePtr

	if err != nil {
		log.Fatal(err)
	}

	defer Db.Close()

	// check if table structure exists and if not create it
	if !checkTablesPresent() {
		log.Println("[INFO] Initial setup: creating needed tables")
		createTables()
	}

	// check if at least one admin account exists and if not create the default one (admin/admin)
	if !checkIfAdminUserExists() {
		createInitialAccount()
		log.Println("[INFO] Default admin account created")
		log.Println("[INFO] Username: admin")
		log.Println("[INFO] Password: admin")
		log.Println("[INFO] PLEASE CHANGE THE PASSWORD ON FIRST LOGIN!")
	}

	router := mux.NewRouter().StrictSlash(true)

	// metrics route for monitoring
	router.Path("/metrics").Handler(promhttp.Handler())

	router.HandleFunc("/auth/", home)
	router.HandleFunc("/auth/login", login).Methods("POST")
	router.HandleFunc("/auth/logout", logout).Methods("POST")
	router.HandleFunc("/auth/account/list", listAccounts).Methods("POST")
	router.HandleFunc("/auth/account/create", createAccount).Methods("POST")
	router.HandleFunc("/auth/account/modify", modifyAccount).Methods("POST")
	router.HandleFunc("/auth/account/modifyPassword", modifyPassword).Methods("POST")
	router.HandleFunc("/auth/account/delete", deleteAccount).Methods("POST")
	router.HandleFunc("/auth/verifyToken", verify).Methods("POST")

	log.Fatal(http.ListenAndServe(":8080", router))
}
