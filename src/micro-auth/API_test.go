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

func _generateValidToken(username string, role int, email string) string {

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
		panic(signingErr)
	}

	return tokenString
}

func setupMockDbData() {
	_, insertErr := Db.Exec("INSERT INTO users VALUES" +
		"('admin"+TestId+"','8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918', 0,'admin@root.fr'), " +
		"('user"+TestId+"','04f8996da763b7a969b1028ee3007569eaf3a635486ddab211d512c85b9df8fb', 1,'user@root.fr')")

	if insertErr != nil {
		panic(insertErr.Error())
	}
}

func setupMockSessionDbData() (string, string) {
	adminToken := _generateValidToken("admin", RoleAdmin, "admin@root.fr")
	userToken := _generateValidToken("user", RoleAnnotator, "user@root.fr")

	_, insertErr := Db.Exec("INSERT INTO sessions (token) VALUES" +
		"('"+adminToken+"'), " +
		"('"+userToken+"')")

	if insertErr != nil {
		panic(insertErr.Error())
	}

	return adminToken, userToken
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
	assert.Equal(t, RoleAdmin, response.Role)

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

func TestVerifyInvalidBodyFormat(t *testing.T) {
	setupMockDbData()
	loginRecorder := _login(t, "admin"+TestId, "admin")
	assert.Equal(t, http.StatusOK, loginRecorder.Code)

	jsonData := []byte("bad format")

	request := &http.Request{
		Method: http.MethodPost,
		Body: ioutil.NopCloser(bytes.NewBuffer(jsonData)),
	}

	checkRecorder := httptest.NewRecorder()

	verify(checkRecorder, request)

	assert.Equal(t, http.StatusBadRequest, checkRecorder.Code)

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

	assert.Equal(t, http.StatusBadRequest, checkRecorder.Code)

	cleanupDb()
}

func TestVerifyValidTokenNotInSessions(t *testing.T) {
	setupMockDbData()

	token := _generateValidToken("admin"+TestId, RoleAdmin, "admin@root.fr")

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
	responseBody := checkRecorder.Body.Bytes()

	assert.Equal(t, http.StatusUnauthorized, checkRecorder.Code)
	assert.Equal(t, "[MICRO-AUTH] Session invalid/expired", string(responseBody))

	cleanupDb()
}

func _create_account(t *testing.T, account *AccountCreationRequest) *httptest.ResponseRecorder {

	jsonData, jsonErr := json.Marshal(account)
	if jsonErr != nil {
		t.Fatal(jsonErr.Error())
	}

	request := &http.Request{
		Method: http.MethodPost,
		Body: ioutil.NopCloser(bytes.NewBuffer(jsonData)),
	}

	recorder := httptest.NewRecorder()

	createAccount(recorder, request)

	return recorder
}

func TestCreateAccountOk(t *testing.T) {
	setupMockDbData()
	adminToken, _ := setupMockSessionDbData()

	recorder := _create_account(t, &AccountCreationRequest{
		AdminToken: adminToken,
		Username: "naruto"+TestId,
		Password: "test",
		Role: RoleAnnotator,
		Email: "naruto@root.fr",
	})

	assert.Equal(t, http.StatusOK, recorder.Code)
	responseBody := recorder.Body.Bytes()
	response := AuthResponse{}

	json.Unmarshal(responseBody, &response)

	assert.Equal(t, "naruto"+TestId, response.Username)
	assert.Equal(t, "naruto@root.fr", response.Email)
	assert.Equal(t, RoleAnnotator, response.Role)

	cleanupDb()
}

func TestCreateAccountEmptyField(t *testing.T) {
	setupMockDbData()
	adminToken, _ := setupMockSessionDbData()

	recorder := _create_account(t, &AccountCreationRequest{
		AdminToken: adminToken,
		Username: "naruto"+TestId,
		Password: "",
		Role: RoleAnnotator,
		Email: "naruto@root.fr",
	})

	responseBody := recorder.Body.Bytes()

	assert.Equal(t, http.StatusBadRequest, recorder.Code)
	assert.Equal(t, "[MICRO-AUTH] Wrong request body format, validation failed", string(responseBody))

	cleanupDb()
}

func TestCreateAccountInsufficientPermissions(t *testing.T) {
	setupMockDbData()
	_, userToken := setupMockSessionDbData()

	recorder := _create_account(t, &AccountCreationRequest{
		AdminToken: userToken,
		Username: "naruto"+TestId,
		Password: "test",
		Role: RoleAnnotator,
		Email: "naruto@root.fr",
	})

	responseBody := recorder.Body.Bytes()

	assert.Equal(t, http.StatusUnauthorized, recorder.Code)
	assert.Equal(t, "[MICRO-AUTH] Insufficient permissions to create an account", string(responseBody))

	cleanupDb()
}

func TestCreateAccountAlreadyExists(t *testing.T) {
	setupMockDbData()
	adminToken, _ := setupMockSessionDbData()

	recorder := _create_account(t, &AccountCreationRequest{
		AdminToken: adminToken,
		Username: "admin"+TestId,
		Password: "toto",
		Role: RoleAdmin,
		Email: "admin@root.fr",
	})

	responseBody := recorder.Body.Bytes()

	assert.Equal(t, http.StatusUnauthorized, recorder.Code)
	assert.Equal(t, "[MICRO-AUTH] Username or email already exists", string(responseBody))

	cleanupDb()
}
