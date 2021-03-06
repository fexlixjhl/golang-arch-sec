package main

import (
	"encoding/json"
	"log"
	"net/http"
)

type person struct {
	First string
}

func main() {

	/* p1 := person{
		First: "Jenny",
	}

	p2 := person{
		First: "James",
	}

	xp := []person{p1, p2}

	bs, err := json.Marshal(xp)
	if err != nil {
		log.Panic(err)
	}

	fmt.Println("PRINT JSON", string(bs))

	xp2 := []person{}

	err = json.Unmarshal(bs, &xp2)

	if err != nil {
		log.Panic(err)
	}

	fmt.Println("back into a Go data structure", xp2) */

	http.HandleFunc("/encode", encode)
	http.HandleFunc("/decode", decode)
	http.ListenAndServe(":8080", nil)

}

func encode(w http.ResponseWriter, r *http.Request) {
	p1 := person{
		First: "Jenny",
	}
	
	p2 := person{
		First: "James",
	}
	people := []person{p1, p2}
	err := json.NewEncoder(w).Encode(people)
	
	if err != nil {
		log.Println("Encoded bad data", err)
	}

}

func decode(w http.ResponseWriter, r *http.Request) {
	var people []person
	err :=  json.NewDecoder(r.Body).Decode(&people)
	if err != nil {
		log.Println("Decoded bad data", err)
	}
	
	log.Println("People:", people)
}
