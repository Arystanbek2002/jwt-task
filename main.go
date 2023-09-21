package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	b64 "encoding/base64"

	"github.com/arystanbek2002/jwt-task/models"
	store "github.com/arystanbek2002/jwt-task/storage"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

type APIError struct {
	Error string `json:"error"`
}

type PairResponse struct {
	Access    string    `json:"access"`
	Referesh  string    `json:"refresh"`
	ExpiresAt time.Time `json:"refresh_expire_at"`
}

type PairRequest struct {
	Access  string `json:"access"`
	Refresh string `json:"refresh"`
}

var (
	storage *store.Storage
	ctx     = context.Background()
	dummy   = "dummy"
)

type Claims struct {
	GUID string `json:"guid"`
	UUID string `json:"uuid"`
	jwt.RegisteredClaims
}

func generateJWT(guid string, uuid string, t time.Time, secretName string) (string, error) {
	claims := &Claims{
		GUID: guid,
		UUID: uuid,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(t),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	tokenString, err := token.SignedString([]byte(os.Getenv(secretName)))
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func VerifyJWT(jwtString, secret string) (*Claims, error) {
	claims := &Claims{}
	_, err := jwt.ParseWithClaims(jwtString, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv(secret)), nil
	})
	return claims, err
}

func main() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatalf("Error loading .env file: %s", err)
	}

	client, err := mongo.Connect(ctx, options.Client().ApplyURI("mongodb://localhost:27017"))
	if err != nil {
		panic(err)
	}

	storage = store.NewStorage(ctx, client)
	router := mux.NewRouter()

	router.HandleFunc("/getToken/{guid}", handleGetToken)
	router.HandleFunc("/refreshToken", handleRefreshToken)

	port := ":8080"

	fmt.Println("Server running on port " + port)

	if err = http.ListenAndServe(port, router); err != nil {
		log.Fatal("error starting server " + err.Error())
	}
}

func handleGetToken(w http.ResponseWriter, r *http.Request) {
	guid, ok := mux.Vars(r)["guid"] //user id in request url
	if !ok {
		WriteJSON(w, http.StatusBadRequest, APIError{Error: "no guid in request's url"})
		return
	}
	generatePair(guid, w) //gunction that creates pair of tokens
}

func generatePair(guid string, w http.ResponseWriter) {
	pair_uuid := uuid.New().String() //identifier of pair
	pair_uuid = strings.Replace(pair_uuid, "-", "", -1)

	refreshEnd := uuid.New().String() //end part of refresh token
	refreshEnd = strings.Replace(refreshEnd, "-", "", -1)

	t := time.Now()
	tAcc := t.Add(10 * time.Minute) //expiration time of access token
	tRef := t.Add(336 * time.Hour)  //expiration time of refresh token

	access, err := generateJWT(guid, pair_uuid, tAcc, "ACCESS_SECRET") //generate jwt with pair id and user id
	if err != nil {
		WriteJSON(w, http.StatusInternalServerError, APIError{Error: "error while creating JWT"})
		return
	}

	refresh := pair_uuid + refreshEnd //refresh token consists of pair id and its own uuid

	bytes, err := bcrypt.GenerateFromPassword([]byte(refresh), 14) //hashing refresh token to store it in bd
	if err != nil {
		WriteJSON(w, http.StatusInternalServerError, APIError{Error: "error while hashing" + err.Error()})
		return
	}
	refreshHash := string(bytes)

	//if user doesn't exist, creates new row
	_, err = storage.InsertUser(ctx, &models.User{Guid: guid, RefreshToken: refreshHash, RefreshFamily: []string{refreshHash}, ExpiresAt: tRef})
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			//if user exists updates row and adds new value to token family
			user, err := storage.GetUser(ctx, guid)
			if err != nil {
				WriteJSON(w, http.StatusBadRequest, APIError{Error: err.Error()})
				return
			}
			user.RefreshFamily = append(user.RefreshFamily, refreshHash)
			_, err = storage.UpdateUser(ctx, &models.User{Guid: guid, RefreshToken: refreshHash, RefreshFamily: user.RefreshFamily, ExpiresAt: tRef})
			if err != nil {
				WriteJSON(w, http.StatusInternalServerError, APIError{Error: err.Error()})
				return
			}
		} else {
			WriteJSON(w, http.StatusInternalServerError, APIError{Error: err.Error()})
			return
		}
	}

	resp := &PairResponse{
		//encode refresh token to base64
		Referesh:  b64.StdEncoding.EncodeToString([]byte(refresh)), //actually must be in httponly cookie
		Access:    access,
		ExpiresAt: tRef,
	}
	WriteJSON(w, http.StatusOK, resp)
}

func handleRefreshToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		//actually refresh must be in httponly cookie
		WriteJSON(w, http.StatusBadRequest, APIError{Error: "not method post, refresh and access tokens must be in request's body"})
		return
	}
	req := new(PairRequest)
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		WriteJSON(w, http.StatusBadRequest, APIError{Error: "decoding error"})
		return
	}
	accClaims, err1 := VerifyJWT(req.Access, "ACCESS_SECRET")
	//check if token error due to expiration and not signature invalidness
	//even if access token expired, user still can refresh token if it's valid
	//don't check token for validity because it will generate error anyway if not valid
	if err1 != nil && !errors.Is(err1, jwt.ErrTokenExpired) {
		WriteJSON(w, http.StatusBadRequest, APIError{Error: "invalid token access " + err1.Error()})
		return
	}

	refreshByte, err := b64.StdEncoding.DecodeString(req.Refresh) //decoding refresh token
	if err != nil {
		WriteJSON(w, http.StatusBadRequest, APIError{Error: fmt.Sprintf("decoding error %s", err.Error())})
		return
	}
	req.Refresh = string(refreshByte)
	//UUID and GUID is the same thing, but in this context GUID user id and UUID pair identifier
	//checks if pair identifier is same
	if req.Refresh[:32] != accClaims.UUID {
		//user can't edit access token without making jwt invalid
		//also he can't edit refresh token, since it kept in bd and won't match
		WriteJSON(w, http.StatusBadRequest, APIError{Error: "invalid token pair"})
		return
	}
	//retrieves user data from bd
	user, err := storage.GetUser(ctx, accClaims.GUID)
	if err != nil {
		WriteJSON(w, http.StatusBadRequest, APIError{Error: err.Error()})
		return
	}
	//if instead of refresh token there is dummy value means that refresh token expired or token pair was stolen
	if user.RefreshToken == dummy {
		WriteJSON(w, http.StatusBadRequest, APIError{Error: "refresh token no longer valid, login again"})
		return
	}
	if time.Now().After(user.ExpiresAt) {
		//if refresh token expired, turn refresh token to dummy and delete token family
		_, err = storage.UpdateUser(ctx, &models.User{Guid: accClaims.GUID, RefreshToken: dummy, RefreshFamily: []string{}, ExpiresAt: user.ExpiresAt})
		if err != nil {
			log.Printf("error while changing refresh Token to Dummy %s", err.Error())
			WriteJSON(w, http.StatusInternalServerError, APIError{Error: "smth went wrong"})
			return
		}
		WriteJSON(w, http.StatusBadRequest, APIError{Error: "refresh token expired, login again"})
		return
	}
	//comparing 2 hash refresh tokens
	err = bcrypt.CompareHashAndPassword([]byte(user.RefreshToken), []byte(req.Refresh))
	if err != nil {
		//if tokens don't match, check if this token is old
		for _, token := range user.RefreshFamily {
			err = bcrypt.CompareHashAndPassword([]byte(token), []byte(req.Refresh))
			if err != nil {
				//if it's old means that tolkens were stolen, deliting family and turning refresh token to dummy
				_, err = storage.UpdateUser(ctx, &models.User{Guid: accClaims.GUID, RefreshToken: dummy, RefreshFamily: []string{}, ExpiresAt: user.ExpiresAt})
				if err != nil {
					log.Printf("error while changing refresh Token to Dummy %s", err.Error())
					WriteJSON(w, http.StatusInternalServerError, APIError{Error: "smth went wrong"})
					return
				}
				WriteJSON(w, http.StatusBadRequest, APIError{Error: "refresh token no longer valid, login again"})
				return
			}
		}
		//if it's too old token or edited one, just ignore it and skip request
		WriteJSON(w, http.StatusBadRequest, APIError{Error: "refresh token invalid, login again"})
		return
	}
	//if everything ok return 2 new tokens, old token becomes invalid
	generatePair(accClaims.GUID, w)
}

func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	err := json.NewEncoder(w).Encode(v)
	if err != nil {
		log.Println(err.Error())
	}
}
