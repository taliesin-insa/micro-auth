package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func setupMockDbData() {
	_, insertErr := Db.Exec("INSERT INTO users VALUES" +
		"('admin','8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918', 0,'admin@root.fr'), " +
		"('user','04f8996da763b7a969b1028ee3007569eaf3a635486ddab211d512c85b9df8fb', 1,'user@root.fr')")

	if insertErr != nil {
		panic(insertErr.Error())
	}
}

func cleanupDb() {
	_, deleteErr := Db.Exec("DELETE FROM users")

	if deleteErr != nil {
		panic(deleteErr.Error())
	}
}

func TestMain(m *testing.M) {

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

	setupMockDbData()

	m.Run()

	cleanupDb()
	Db.Close()

}

func TestSuccessfulLogin(t *testing.T) {
	requestPayload := AuthRequest{
		Username: "admin",
		Password: "admin",
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

	assert.Equal(t, http.StatusOK, recorder.Code)
	responseBody := recorder.Body.Bytes()
	response := AuthResponse{}

	json.Unmarshal(responseBody, &response)

	assert.Equal(t, "admin", response.Username)
	assert.Equal(t, "admin@root.fr", response.Email)
	assert.Equal(t, 0, response.Role)

}

func TestLoginWrongPassword(t *testing.T) {
	requestPayload := AuthRequest{
		Username: "admin",
		Password: "non",
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

	assert.Equal(t, http.StatusUnauthorized, recorder.Code)
}

func TestLoginNonExistingUser(t *testing.T) {
	requestPayload := AuthRequest{
		Username: "toto",
		Password: "ah",
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

	assert.Equal(t, http.StatusUnauthorized, recorder.Code)

}