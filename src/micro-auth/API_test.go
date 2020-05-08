package main

import (
	"database/sql"
	"log"
	"os"
	"testing"
)

func setupMockDbData() {
	_, insertErr := Db.Exec("INSERT INTO users VALUES" +
		"('admin','8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918','0','admin@root.fr'), " +
		"('user','04f8996da763b7a969b1028ee3007569eaf3a635486ddab211d512c85b9df8fb','1','user@root.fr')")

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

func TestConnect(t *testing.T) {

}
