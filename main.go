package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/subosito/gotenv"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"os"
	"projetfederateur/driver"
	"projetfederateur/models"
	"projetfederateur/utils"
	"regexp"
	"strconv"
	"strings"
	"time"
)


var db *sql.DB

func init() {
	gotenv.Load()
}
func main() {
	db = driver.ConnectDB()
	router := mux.NewRouter()
	router.HandleFunc("/signup", signup).Methods("POST")
	router.HandleFunc("/login", login).Methods("POST")
	router.HandleFunc("/me", TokenVerifyMiddleWare(protectedEndpoint)).Methods("get")
	router.HandleFunc("/me/reports", TokenVerifyMiddleWare(getmyreports)).Methods("get")
	router.HandleFunc("/me/reports", TokenVerifyMiddleWare(createReport)).Methods("post")
	router.HandleFunc("/locations", TokenVerifyMiddleWare(addLocation)).Methods("post")
	router.HandleFunc("/users/{id:[0-9]+}/reports", TokenVerifyMiddleWare(getreports)).Methods("get")
	router.HandleFunc("/users/{id:[0-9]+}", TokenVerifyMiddleWare(getuserbyid)).Methods("get")


	log.Fatal(http.ListenAndServe(":9999",router))

}

func isEmailValid(e string) bool {
	var emailRegex = regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+\\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")

	if len(e) < 3 && len(e) > 254 {
		return false
	}
	return emailRegex.MatchString(e)
}
func signup(w http.ResponseWriter, r *http.Request)  {
	var user models.User
	//var error models.Error




	json.NewDecoder(r.Body).Decode(&user)
	if isEmailValid(user.Email) != true || user.Email == ""{
			error := "Email Error"
			utils.ResponseWithError(w, http.StatusBadRequest, error)
			return
	}
	if user.Password == "" {
		error := "Pick Better Password"
		utils.ResponseWithError(w, http.StatusBadRequest, error)
		return
	}
	if user.FirstName == "" {
		error := "Your Correct Name Please"
		utils.ResponseWithError(w, http.StatusBadRequest, error)
		return
	}
	if user.LinkPdp == "" {
		error := "Your Correct Name Please"
		utils.ResponseWithError(w, http.StatusBadRequest, error)
		return
	}


	hash , err := bcrypt.GenerateFromPassword([]byte(user.Password),10)
	if err != nil {
		log.Fatal("[!] something went wrong")
	}
	user.Password = string(hash)
	stmt := "insert into users (email, password, firstname, lastname, linkpdp) values($1, $2, $3, $4, $5) RETURNING id;"
	err = db.QueryRow(stmt, user.Email, user.Password, user.FirstName, user.LastName,  user.LinkPdp).Scan(&user.ID)
	if err != nil {
		error := "Error in the backend"
		utils.ResponseWithError(w, http.StatusInternalServerError, error)
		return
	}
	user.Password = ""


	utils.ResponseJSON(w, user)


}

func GenerateToken(user models.User) (string, error) {
	var err error
	secret := os.Getenv("SECRET")
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email":user.Email,
		"iss":"course",
	})
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil{
		log.Fatal("[!] Token Generation Error")
	}
	return tokenString, nil

}
func login(w http.ResponseWriter, r *http.Request)  {
	var user models.User
	var jwt models.JWT
	//var error models.Error

	json.NewDecoder(r.Body).Decode(&user)
	if isEmailValid(user.Email) != true || user.Email == ""{
		error := "Email Error, Re-enter Your Email"
		utils.ResponseWithError(w, http.StatusBadRequest, error)
		return
	}
	if user.Password == "" {
		error := "Enter Password"
		utils.ResponseWithError(w, http.StatusBadRequest, error)
		return
	}
	password := user.Password
	row := db.QueryRow("select * from users where email=$1", user.Email)
	err := row.Scan(&user.ID, &user.Email, &user.Password, &user.FirstName, &user.LastName, &user.LinkPdp)
	if err != nil {

		if err == sql.ErrNoRows {
			error := "The user Doesn't exist"
			utils.ResponseWithError(w, http.StatusBadRequest, error)
			return
		} else {
			log.Fatal(err)
		}
	}
	hashedPassword := user.Password
	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		error := "Wrong Password"
		utils.ResponseWithError(w, http.StatusUnauthorized, error)
		return
	}
	token, err := GenerateToken(user)
	if err != nil {
		log.Fatal(err)
	}
	w.WriteHeader(http.StatusOK)
	jwt.Token = token
	utils.ResponseJSON(w, jwt)

}
func protectedEndpoint(w http.ResponseWriter, r *http.Request)  {

	fmt.Println("secret invoked")
	var user models.User
	Email := CurrentUser(r,user)

	row := db.QueryRow(`select * from users where email=$1`, Email)
	err := row.Scan(&user.ID, &user.Email, &user.Password, &user.FirstName, &user.LastName, &user.LinkPdp)
	if err != nil {
		log.Fatal("error")
	}
	user.Password = ""
	utils.ResponseJSON(w, user)

}
func TokenVerifyMiddleWare(next http.HandlerFunc) http.HandlerFunc  {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request){

		//var errorObject models.Error
		authHeader := r.Header.Get("Authorization")
		bearerToken := strings.Split(authHeader, " ")
		if len(bearerToken) == 2 {

			authToken := bearerToken[1]
			token, error := jwt.Parse(authToken, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("[!] error token")
				}
				return []byte(os.Getenv("SECRET")),nil
			})
			if error != nil {
				errorObject := error.Error()
				utils.ResponseWithError(w, http.StatusUnauthorized, errorObject)
				return
			}
			if token.Valid {
				next.ServeHTTP(w , r)
			} else {
				errorObject := error.Error()
				utils.ResponseWithError(w, http.StatusUnauthorized, errorObject)
				return
			}
		} else {
			errorObject := "[!] Invalid Token"
			utils.ResponseWithError(w, http.StatusUnauthorized, errorObject)
		}
	})

}


func ParseToken(tokenStr string) (string, error) {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("SECRET")), nil
	})
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		email := claims["email"].(string)
		return email, nil
	} else {
		return "", err
	}
}
func createReport(w http.ResponseWriter, r *http.Request){
	var user models.User
	var report models.Report
	var message models.Error
	Email := CurrentUser(r,user)
	row := db.QueryRow(`select * from users where email=$1`, Email)
	err := row.Scan(&user.ID, &user.Email, &user.Password, &user.FirstName, &user.LastName, &user.LinkPdp)
	if err != nil {
		log.Fatal("error 1")
	}

	json.NewDecoder(r.Body).Decode(&report)
	userId := user.ID
	locationId, err := getlocationid(report.Lat,report.Lnt)
	if err != nil  {
		message.Message = "Enter correct geolocation "
		utils.ResponseJSON(w, message)
	}
	now := time.Now()
	stmt := "insert into reports (Title, Type,Description,Attachment,User_id,Location_id,created_at) values($1, $2, $3, $4, $5, $6,$7) RETURNING id;"
	err = db.QueryRow(stmt,report.Title, report.Type, report.Description, report.Attachment, userId, locationId, now ).Scan(&report.ID)
	if err != nil {
		log.Fatal(err)
	}
	message.Message = "Post Created"


	utils.ResponseJSON(w, message)


}
func addLocation(w http.ResponseWriter, r *http.Request)  {
	var location models.Location
	var message models.Error
	json.NewDecoder(r.Body).Decode(&location)
	stmt := "insert into markers ( name, address, lat, lng, type) values($1, $2, $3, $4, $5) RETURNING id;"
	err := db.QueryRow(stmt,location.Name, location.Address, location.Lat,location.Lnt, location.Type).Scan(&location.ID)
	if err != nil {
		log.Fatal(err)
	}
	message.Message = "Post Created"


	utils.ResponseJSON(w, message)
}

func getmyreports(w http.ResponseWriter, r *http.Request){
	var user models.User
	var report models.Report
	Email := CurrentUser(r,user)

	row := db.QueryRow(`select * from users where email=$1`, Email)
	err := row.Scan(&user.ID, &user.Email, &user.Password, &user.FirstName, &user.LastName, &user.LinkPdp)
	if err != nil {
		log.Fatal("error 1")
	}

	row2, err := db.Query(`select * from reports where user_id=$1`, user.ID)
	userId := 0
	var date time.Time
	var locationId int
	reports := make([]models.Report, 0)

	for row2.Next() {
		err := row2.Scan(&report.ID,&report.Title,&report.Type,&report.Description, &report.Attachment, &userId, &locationId, &date  )
		if err != nil {
			log.Fatal("error db")

		}
		report.Lat,report.Lnt = getgeolocationfromid(locationId)

		reports =append (reports, report)


	}
	if err != nil {
		log.Fatal("error db")
	}
	utils.ResponseJSON(w, reports)

}
func getreports(w http.ResponseWriter, r *http.Request)  {
	var report models.Report

	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])

	row2, err := db.Query(`select * from reports where user_id=$1`, id)
	if err != nil {
		log.Fatal("error db")
	}
	userId := 0
	//var date time.Time
	var locationId int
	reports := make([]models.Report, 0)

	for row2.Next() {
		err := row2.Scan(&report.ID,&report.Title,&report.Type,&report.Description, &report.Attachment, &userId, &locationId, &report.CreatedAt  )
		if err != nil {
			log.Fatal("error db")

		}
		report.Lat,report.Lnt = getgeolocationfromid(locationId)

		reports =append (reports, report)


	}
	if err != nil {
		log.Fatal("error db")
	}
	utils.ResponseJSON(w, reports)

}
func getlocationid (lat float64, lgt float64) (int, error){
	var location models.Location

	fmt.Println(lat,lgt)
	row := db.QueryRow(`select * from markers where lat=$1 and lng=$2`, lat,lgt)
	err := row.Scan(&location.ID,&location.Name,&location.Address,&location.Lat,&location.Lnt,&location.Type)
	if err != nil {
		log.Fatal(err)
	}
	return location.ID, err
}

func getgeolocationfromid(id int ) (float64, float64) {
	var location models.Location


	row := db.QueryRow(`select * from markers where id=$1`, id)
	err := row.Scan(&location.ID,&location.Name,&location.Address,&location.Lat,&location.Lnt,&location.Type)
	if err != nil {
		log.Fatal(err)
	}
	return location.Lat,location.Lnt
}

func CurrentUser(r *http.Request, user models.User) string {
	authHeader := r.Header.Get("Authorization")
	bearerToken := strings.Split(authHeader, " ")


	authToken := bearerToken[1]
	Email, err := ParseToken(authToken)

	if err != nil {
		log.Fatal("error")
	}
	return Email
}
func getuserbyid(w http.ResponseWriter, r *http.Request)  {

}

