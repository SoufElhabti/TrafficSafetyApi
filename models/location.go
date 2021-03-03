package models

type Location struct {
	ID int `json:"id"`
	Name string `json:"name"`
	Address string `json:"address"`
	Lat float64 `json:"lat"`
	Lnt float64 `json:"lnt"`
	Type string `json:"type"`

}