package models

type User struct {
	ID int `json:"id"`
	Email string `json:"email"`
	Password string `json:"password"`
	FirstName string `json:"firstname"`
	LastName string `json:"lastname"`
	LinkPdp string `json:"LinkPdp"`

}
