package models

import "time"

type Report struct {
	ID int `json:"id"`
	Title string `json:"Title"`
	Type string `json:"Type"`
	Description string `json:"description"`
	Attachment string `json:"Attachment"`
	Lat float64 `json:"lat"`
	Lnt float64 `json:"lnt"`
	CreatedAt time.Time `json:"created_at" bson:"created_at"`

}
