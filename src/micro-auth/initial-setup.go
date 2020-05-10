package main

import (
	"log"
	"strconv"
)

func checkTablesPresent() bool {
	showTablesStatement, showErr := Db.Query("SHOW TABLES")

	if showErr != nil {
		log.Fatalf("[FATAL] Error while checking tables: %v", showErr.Error())
	}

	defer showTablesStatement.Close()

	var table string
	var isUserTablePresent = false
	var isSessionsTablePresent = false

	for showTablesStatement.Next() {
		tableErr := showTablesStatement.Scan(&table)

		if tableErr != nil {
			log.Fatalf("[FATAL] Error while checking tables: %v", tableErr.Error())
		}

		if table == "users" {
			isUserTablePresent = true
		} else if table == "sessions" {
			isSessionsTablePresent = true
		}
	}

	return isUserTablePresent && isSessionsTablePresent
}

func createTables() {
	_, tableUsersErr := Db.Exec("CREATE TABLE users(username varchar(100), password varchar(255), role int, email varchar(255), primary key(username));")

	if tableUsersErr != nil {
		log.Fatalf("[FATAL] Error while creating table users: %v", tableUsersErr.Error())
	}

	_, tableSessionsErr := Db.Exec("CREATE TABLE sessions(id int not null auto_increment, token varchar(400), primary key(id));")

	if tableSessionsErr != nil {
		log.Fatalf("[FATAL] Error while creating table sessions: %v", tableSessionsErr.Error())
	}

}

func checkIfAdminUserExists() bool {
	selectStatement, selectErr := Db.Query("SELECT count(username) FROM users WHERE role = 0")

	if selectErr != nil {
		log.Fatalf("[FATAL] Error while checking if admin user exists): %v", selectErr.Error())
	}

	defer selectStatement.Close()

	var count string

	sessionQueryErr := selectStatement.Scan(&count)
	intCount, sessionCountErr := strconv.Atoi(count)

	if sessionQueryErr != nil {
		log.Fatalf("[FATAL] Error while querying admin users: %v", sessionQueryErr.Error())
	}

	if sessionCountErr != nil {
		log.Fatal("[FATAL] unexpected value received from checkIfAccountExist")
	}

	return intCount > 0
}

func createInitialAccount() {
	_, insertErr := Db.Exec("INSERT INTO users VALUES" +
		"('admin','8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918', 0,'');")

	if insertErr != nil {
		log.Fatalf("[FATAL] could not create initial admin account, %v", insertErr.Error())
	}
}