package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"
)

var TestId string

func setupMockDbData() {
	_, insertErr := Db.Exec("INSERT INTO users VALUES" +
		"('admin"+TestId+"','8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918', 0,'admin@root.fr'), " +
		"('user"+TestId+"','04f8996da763b7a969b1028ee3007569eaf3a635486ddab211d512c85b9df8fb', 1,'user@root.fr')")

	if insertErr != nil {
		panic(insertErr.Error())
	}
}

func cleanupDb() {
	_, deleteErr := Db.Exec("DELETE FROM users")
	_, deleteSessionsErr := Db.Exec("DELETE FROM sessions")

	if deleteErr != nil || deleteSessionsErr != nil {
		panic(deleteErr.Error())
	}
}

func TestMain(m *testing.M) {
	// generate a unique identifier for values inserted in db
	// to prevent concurrency issues
	now := time.Now()
	nsec := now.UnixNano()
	TestId = strconv.FormatInt(nsec, 10)

	var passwordValue string

	if value, isDbPasswordPresent := os.LookupEnv("DB_PASSWORD") ; !isDbPasswordPresent {
		panic("DB_PASSWORD is not present in env, aborting.")
	} else {
		passwordValue = value
	}

	HMACSecret = []byte("placeholder_secret")

	databasePtr, err := sql.Open("mysql", "test:"+passwordValue+"@tcp(10.133.33.51:3306)/test")
	Db = databasePtr

	if err != nil {
		log.Fatal(err)
	}


	code := m.Run()

	cleanupDb()
	Db.Close()

	os.Exit(code)
}

func _login(t *testing.T, username string, password string) *httptest.ResponseRecorder {
	requestPayload := AuthRequest{
		Username: username,
		Password: password,
	}

	jsonData, jsonErr := json.Marshal(&requestPayload)
	if jsonErr != nil {
		t.Fatal(jsonErr.Error())
	}

	request := &http.Request{
		Method: http.MethodPost,
		Body: ioutil.NopCloser(bytes.NewBuffer(jsonData)),
	}

	recorder := httptest.NewRecorder()

	login(recorder, request)

	return recorder
}

func TestSuccessfulLogin(t *testing.T) {
	setupMockDbData()

	recorder := _login(t, "admin"+TestId, "admin")

	assert.Equal(t, http.StatusOK, recorder.Code)
	responseBody := recorder.Body.Bytes()
	response := AuthResponse{}

	json.Unmarshal(responseBody, &response)

	assert.Equal(t, "admin"+TestId, response.Username)
	assert.Equal(t, "admin@root.fr", response.Email)
	assert.Equal(t, 0, response.Role)

	cleanupDb()
}

func TestLoginWrongPassword(t *testing.T) {
	setupMockDbData()

	recorder := _login(t, "admin"+TestId, "nope")

	assert.Equal(t, http.StatusUnauthorized, recorder.Code)

	cleanupDb()
}

func TestLoginNonExistingUser(t *testing.T) {
	setupMockDbData()

	recorder := _login(t, "null", "admin")

	assert.Equal(t, http.StatusUnauthorized, recorder.Code)

	cleanupDb()
}

func TestVerifyValidToken(t *testing.T) {
	setupMockDbData()

	loginRecorder := _login(t, "admin"+TestId, "admin")
	assert.Equal(t, http.StatusOK, loginRecorder.Code)

	responseBody := loginRecorder.Body.Bytes()
	loginResponse := AuthResponse{}

	json.Unmarshal(responseBody, &loginResponse)

	requestPayload := VerifyRequest{
		Token: loginResponse.Token,
	}

	jsonData, jsonErr := json.Marshal(&requestPayload)
	if jsonErr != nil {
		t.Fatal(jsonErr.Error())
	}

	request := &http.Request{
		Method: http.MethodPost,
		Body: ioutil.NopCloser(bytes.NewBuffer(jsonData)),
	}

	checkRecorder := httptest.NewRecorder()

	verify(checkRecorder, request)

	assert.Equal(t, http.StatusOK, checkRecorder.Code)

	cleanupDb()
}

func TestVerifyInvalidToken(t *testing.T) {
	setupMockDbData()

	loginRecorder := _login(t, "admin"+TestId, "admin")
	assert.Equal(t, http.StatusOK, loginRecorder.Code)

	responseBody := loginRecorder.Body.Bytes()
	loginResponse := AuthResponse{}

	json.Unmarshal(responseBody, &loginResponse)

	requestPayload := VerifyRequest{
		Token: "bad_token",
	}

	jsonData, jsonErr := json.Marshal(&requestPayload)
	if jsonErr != nil {
		t.Fatal(jsonErr.Error())
	}

	request := &http.Request{
		Method: http.MethodPost,
		Body: ioutil.NopCloser(bytes.NewBuffer(jsonData)),
	}

	checkRecorder := httptest.NewRecorder()

	verify(checkRecorder, request)

	assert.Equal(t, http.StatusUnauthorized, checkRecorder.Code)

	cleanupDb()
}

func _generateValidToken(t *testing.T, username string, role int, email string) string {

	stdclaims := jwt.StandardClaims{
		IssuedAt: time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, JwtClaims{
		Username: username,
		Role: role,
		Email: email,
		StandardClaims: stdclaims,
	})

	tokenString, signingErr := token.SignedString(HMACSecret)

	if signingErr != nil {
		t.Fatal(signingErr)
	}

	return tokenString
}

func TestVerifyValidTokenNotInSessions(t *testing.T) {
	setupMockDbData()

	token := _generateValidToken(t, "admin"+TestId, RoleAdmin, "admin@root.fr")

	requestPayload := VerifyRequest{
		Token: token,
	}

	jsonData, jsonErr := json.Marshal(&requestPayload)
	if jsonErr != nil {
		t.Fatal(jsonErr.Error())
	}

	request := &http.Request{
		Method: http.MethodPost,
		Body: ioutil.NopCloser(bytes.NewBuffer(jsonData)),
	}

	checkRecorder := httptest.NewRecorder()

	verify(checkRecorder, request)

	assert.Equal(t, http.StatusUnauthorized, checkRecorder.Code)

	cleanupDb()
}