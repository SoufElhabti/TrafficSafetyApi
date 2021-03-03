package driver

import (
	"database/sql"
	"log"
	"os"
	"github.com/lib/pq"
)

var db *sql.DB

func ConnectDB() *sql.DB{
	pgUrl, err := pq.ParseURL(os.Getenv("ELEPHANTSQL_URL"))

	if err != nil {
		log.Fatal(err)
	}
	db, err = sql.Open("postgres",pgUrl )
	if err != nil {
		log.Fatal(err)
	}
	err = db.Ping()
	if err != nil {
		log.Fatal(err)
	}

	return db
}
