package utils

import (
	"encoding/json"
	"net/http"
	"projetfederateur/models"
)

func ResponseWithError(w http.ResponseWriter, status int, message string) {
	var error models.Error

	error.Message = message
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(error)

}
func ResponseJSON(w http.ResponseWriter, data interface{} ){
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}
