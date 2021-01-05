package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gofrs/uuid"
	"io"
	"log"
	"time"
)

type UserClaims struct {
	jwt.StandardClaims
	SessionID int64
}

type key struct {
	key []byte
	created time.Time
}
var currentKid = ""
var keys = map[string]key{}

func main() {
	pass := "12345678"
	hashedPass, err := hashPassword(pass)
	if err != nil {
		panic(err)
	}
	err = comparePassword(pass, hashedPass)
	if err != nil {
		log.Fatalln("Not logged in")
	}

	log.Println("Logged in!")

}

func hashPassword(password string) ([]byte, error) {
	bs, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("Error while generating bcrypt hash from passowrd: %w", err)
	}
	log.Println("Hash:", password, "--", string(bs))
	return bs, nil
}

func comparePassword(password string, hashedPass []byte) error {
	err := bcrypt.CompareHashAndPassword(hashedPass, []byte(password))

	if err != nil {
		return fmt.Errorf("Invalid password: %w", err)
	}
	return nil
}

func signMessage(msg []byte) ([]byte, error){
	h := hmac.New(sha512.New, keys[currentKid].key)
	log.Println("Sig:", h)
	_, err := h.Write(msg)
	if err != nil{
		return nil, fmt.Errorf("Error in signMessage while hashing message; %w", err)
	}

	signature := h.Sum(nil)
	return signature, nil
}

func checkSig(msg, sig []byte) (bool, error){
	newSig, err := signMessage(msg)
	if err != nil {
		return false, fmt.Errorf("Error in checkSig while getting signature of message: %w", err)
	}

	same := hmac.Equal(newSig, sig)
	return same, nil
}

func (u *UserClaims) Valid() error{
	if !u.VerifyExpiresAt(time.Now().Unix(), true){
		return fmt.Errorf("Token has expired")
	}

	if u.SessionID == 0 {
		return fmt.Errorf("Invalid session ID")
	}

	return nil
}


func createToken(c *UserClaims) (string, error) {
	t := jwt.NewWithClaims(jwt.SigningMethodHS512, c)
	signedToken, err := t.SignedString(keys[currentKid].key)
	if err != nil {
		return "", fmt.Errorf("Error in createToken when signing token: %w", err)
	}

	return signedToken, nil
}

func generateNewKey() error{
	newKey := make([]byte, 64)
	_, err := io.ReadFull(rand.Reader, newKey)

	if err != nil {
		return fmt.Errorf("Error in generateNewKey while generating: %w", err)
	}

	uid, err := uuid.NewV4()
	if err != nil {
		return fmt.Errorf("Error in generateNewKey while generating kid: %w", err)
	}

	keys[uid.String()] = key {
		key: newKey,
		created: time.Now(),
	}
	currentKid = uid.String()
	return nil
}



func parseToken(signedToken string) (*UserClaims, error){
	t, err := jwt.ParseWithClaims(signedToken, &UserClaims{}, func(t *jwt.Token) (i interface{}, e error) {
		if t.Method.Alg() != jwt.SigningMethodHS512.Alg() {
			return nil, fmt.Errorf("Invalid signing algorithm")
		}

		kid, ok := t.Header["kid"].(string)
		if !ok{
			return nil, fmt.Errorf("invalid key ID")
		}
		k, ok := keys[kid]
		if !ok{
			return nil, fmt.Errorf("Invalid key ID from keys")
		}

		return k, nil
	})

	if err != nil {
		return nil, fmt.Errorf("Error in parseToken while parsing token: %w", err)
	}

	if !t.Valid {
		return nil, fmt.Errorf("Error in parseToken, token is not valid")
	}

	return t.Claims.(*UserClaims), nil
}