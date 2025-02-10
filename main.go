package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"github.com/mambo-dev/chirpy/internal/auth"
	"github.com/mambo-dev/chirpy/internal/database"
)

func main() {
	godotenv.Load()
	dbURL := os.Getenv("DB_URL")
	JWTSecret := os.Getenv("JWT_SECRET")
	mux := http.NewServeMux()
	server := &http.Server{
		Handler: mux,
		Addr:    ":8080",
	}

	db, err := sql.Open("postgres", dbURL)

	if err != nil {
		log.Fatalf("could not open db:%v\n", err.Error())
	}

	dbQueries := database.New(db)

	apiConfig := apiConfig{}
	apiConfig.JWTSecret = JWTSecret
	apiConfig.dbQueries = dbQueries
	mux.HandleFunc("GET /api/healthz", ok)

	mux.HandleFunc("GET /api/chirps/{chirpID}", apiConfig.getChirp)
	mux.HandleFunc("DELETE /api/chirps/{chirpID}", apiConfig.deleteChirp)
	mux.HandleFunc("GET /api/chirps", apiConfig.getChirps)
	mux.HandleFunc("POST /api/chirps", apiConfig.createChirp)
	mux.HandleFunc("POST /api/users", apiConfig.createUsers)
	mux.HandleFunc("PUT /api/users", apiConfig.updateUser)
	mux.HandleFunc("POST /api/login", apiConfig.login)
	mux.HandleFunc("POST /api/refresh", apiConfig.refresh)
	mux.HandleFunc("POST /api/revoke", apiConfig.revoke)

	handler := http.StripPrefix("/", http.FileServer(http.Dir(".")))
	mux.HandleFunc("GET /admin/metrics", apiConfig.getMetrics)
	mux.HandleFunc("POST /admin/reset", apiConfig.reset)
	mux.Handle("/app/", apiConfig.middlewareMetricsInc(handler))
	fmt.Println("Listening...")
	server.ListenAndServe()

}

type apiConfig struct {
	fileserverHits atomic.Int32
	dbQueries      *database.Queries
	JWTSecret      string
}

func (cfg *apiConfig) getChirp(w http.ResponseWriter, req *http.Request) {
	chirpID := req.PathValue("chirpID")

	chirpUUID, err := uuid.Parse(chirpID)
	if err != nil {
		fmt.Printf("FATAL:%v\n", err.Error())
		respondWithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	chirp, err := cfg.dbQueries.GetChirp(req.Context(), chirpUUID)

	if err != nil {
		fmt.Printf("ERROR: %v\n", err.Error())
		respondWithError(w, http.StatusNotFound, "Could not find chirp")
		return
	}

	respondWithJSON(w, http.StatusOK, chirp)
	return
}

func (cfg *apiConfig) getChirps(w http.ResponseWriter, req *http.Request) {
	chirps, err := cfg.dbQueries.GetChirps(req.Context())

	if err != nil {
		respondWithError(w, http.StatusBadRequest, "could not return chirps")
		return
	}

	respondWithJSON(w, http.StatusOK, chirps)
	return
}

func (cfg *apiConfig) createChirp(w http.ResponseWriter, req *http.Request) {
	type Params struct {
		Body string `json:"body"`
	}

	authToken, err := auth.GetBearerToken(req.Header)

	if err != nil {
		fmt.Printf("FATAL:%v\n", err.Error())
		respondWithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	userID, err := auth.ValidateJWT(authToken, cfg.JWTSecret)

	if err != nil {
		fmt.Printf("ERROR:%v\n", err.Error())
		respondWithError(w, http.StatusUnauthorized, "user is unauthorized")
		return
	}

	decoder := json.NewDecoder(req.Body)
	params := &Params{}

	err = decoder.Decode(params)

	if err != nil {
		fmt.Printf("FATAL:%v\n", err.Error())
		respondWithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	validChirp, err, code := validateChirp(params.Body)

	if err != nil {
		respondWithError(w, code, err.Error())
		return
	}

	chirp, err := cfg.dbQueries.CreateChirp(req.Context(), database.CreateChirpParams{
		Body: validChirp,
		UserID: uuid.NullUUID{
			UUID:  userID,
			Valid: true,
		},
	})

	if err != nil {
		fmt.Printf("ERROR:%v\n", err.Error())
		respondWithJSON(w, http.StatusBadRequest, reqError{
			Error: "could not create the chirp",
		})

		return
	}

	respondWithJSON(w, http.StatusCreated, chirp)

	return

}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, req)
	})
}

func getUserID(r *http.Request) (uuid.UUID, error) {
	userID, ok := r.Context().Value("userID").(uuid.UUID)

	if !ok {
		return uuid.New(), errors.New("could not retrieve user id ")
	}

	return userID, nil
}

func (cfg *apiConfig) getMetrics(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	htmlData := fmt.Sprintf(`<html>
								<body>
									<h1>Welcome, Chirpy Admin</h1>
									<p>Chirpy has been visited %d times!</p>
								</body>
							</html>`, cfg.fileserverHits.Load())

	w.Write([]byte(htmlData))
}

func (cfg *apiConfig) reset(w http.ResponseWriter, req *http.Request) {
	cfg.fileserverHits.Swap(0)
	platform := os.Getenv("PLATFORM")
	if platform != "dev" {
		respondWithError(w, http.StatusForbidden, "reset only allowed in dev mode")
		return
	}
	cfg.dbQueries.DeleteUsers(req.Context())
	w.WriteHeader(http.StatusOK)
}

func ok(w http.ResponseWriter, req *http.Request) {

	req.Header.Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))

}

type reqError struct {
	Error string `json:"error"`
}

type Success struct {
	CleanedBody string `json:"cleaned_body"`
}

func validateChirp(chirp string) (string, error, int) {

	if len(chirp) > 140 {

		return "", errors.New("Chirp is too long"), http.StatusBadRequest
	}

	newString := []string{}
	for _, character := range strings.Split(chirp, " ") {
		stringCharacter := string(character)
		if strings.ToLower(stringCharacter) == "kerfuffle" || strings.ToLower(stringCharacter) == "sharbert" || strings.ToLower(stringCharacter) == "fornax" {
			newString = append(newString, "****")
		} else {
			newString = append(newString, stringCharacter)
		}
	}

	return strings.Join(newString, " "), nil, http.StatusContinue

}

func (cfg *apiConfig) login(w http.ResponseWriter, req *http.Request) {
	type Params struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	decoder := json.NewDecoder(req.Body)
	params := &Params{}

	err := decoder.Decode(params)

	if err != nil {
		fmt.Printf("ERROR: failed to decode params %v\n", err.Error())
		respondWithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	email := params.Email

	user, err := cfg.dbQueries.GetUserByEmail(req.Context(), email)

	if err != nil {
		fmt.Printf("ERROR: invalid email-> %v", err.Error())
		respondWithError(w, http.StatusUnauthorized, "Incorrect email or password")
		return
	}

	err = auth.CheckPasswordHash(params.Password, user.HashedPassword)

	if err != nil {
		fmt.Printf("ERROR: invalid password-> %v", err.Error())
		respondWithError(w, http.StatusUnauthorized, "Incorrect email or password")
		return
	}

	expiresIn := "1h"
	expiresInDuration, err := time.ParseDuration(expiresIn)
	if err != nil {
		fmt.Printf("ERROR: Invalid duration provided -> %v", err.Error())
		respondWithError(w, http.StatusInternalServerError, "Invalid expires in duration")
		return
	}

	JWTToken, err := auth.MakeJWT(user.ID, cfg.JWTSecret, expiresInDuration)

	if err != nil {
		fmt.Printf("ERROR: failed to get token-> %v", err.Error())
		respondWithError(w, http.StatusInternalServerError, "Failed to provide jwt ")
		return
	}

	type UserResponse struct {
		ID           uuid.UUID `json:"id"`
		CreatedAt    time.Time `json:"created_at"`
		UpdatedAt    time.Time `json:"updated_at"`
		Email        string    `json:"email"`
		AccessToken  string    `json:"token"`
		RefreshToken string    `json:"refresh_token"`
	}

	refreshToken, err := auth.MakeRefreshToken()
	if err != nil {
		fmt.Printf("ERROR: failed to generate refresh token-> %v", err.Error())
		respondWithError(w, http.StatusInternalServerError, "Failed to generate refresh token ")
		return
	}

	refreshExpiresIn, err := time.ParseDuration("1440h")

	if err != nil {
		fmt.Printf("FATAL: failed to parse duration-> %v", err.Error())
		respondWithError(w, http.StatusInternalServerError, "Something went wrong ")
		return
	}

	fmt.Println(time.Now().Add(refreshExpiresIn))

	savedRefreshToken, err := cfg.dbQueries.CreateRefreshToken(req.Context(), database.CreateRefreshTokenParams{
		Token: refreshToken,
		UserID: uuid.NullUUID{
			UUID:  user.ID,
			Valid: true,
		},
		ExpiresAt: sql.NullTime{
			Time:  time.Now().Add(refreshExpiresIn),
			Valid: true,
		},
	})

	if err != nil {
		fmt.Printf("ERROR: failed to save refresh token-> %v", err.Error())
		respondWithError(w, http.StatusInternalServerError, "Failed to save refresh token ")
		return
	}

	respondWithJSON(w, http.StatusOK, UserResponse{
		ID:           user.ID,
		CreatedAt:    user.CreatedAt,
		UpdatedAt:    user.UpdatedAt,
		Email:        user.Email,
		AccessToken:  JWTToken,
		RefreshToken: savedRefreshToken.Token,
	})
	return
}

func (cfg *apiConfig) refresh(w http.ResponseWriter, req *http.Request) {
	authHeader := req.Header.Get("Authorization")

	if len(authHeader) < 1 {
		fmt.Printf("ERROR: failed to get refresh token in headers")
		respondWithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	refreshToken := strings.Split(authHeader, " ")[1]

	if len(refreshToken) < 1 {
		fmt.Printf("ERROR: failed to get refresh token in headers instead got %v\n", refreshToken)
		respondWithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	savedRefreshToken, err := cfg.dbQueries.GetRefreshToken(req.Context(), refreshToken)

	if err != nil {
		fmt.Printf("ERROR: failed to get refresh token in database instead got %v\n", err.Error())
		respondWithError(w, http.StatusUnauthorized, "could not get refresh token")
		return

	}

	if savedRefreshToken.RevokedAt.Valid {
		fmt.Printf("ERROR: refresh token revoked")
		respondWithError(w, http.StatusUnauthorized, "refresh token was revoked")
		return
	}

	expiresAt := savedRefreshToken.ExpiresAt.Time
	if time.Now().After(expiresAt) {
		fmt.Printf("ERROR: refresh token expired at %v\n", expiresAt)
		respondWithError(w, http.StatusUnauthorized, "refresh token is expired")
		return
	}

	expiresIn := "1h"
	expiresInDuration, err := time.ParseDuration(expiresIn)
	if err != nil {
		fmt.Printf("ERROR: Invalid duration provided -> %v", err.Error())
		respondWithError(w, http.StatusInternalServerError, "Invalid expires in duration")
		return
	}

	JWTToken, err := auth.MakeJWT(savedRefreshToken.UserID.UUID, cfg.JWTSecret, expiresInDuration)

	if err != nil {
		fmt.Printf("ERROR: failed to get token-> %v", err.Error())
		respondWithError(w, http.StatusInternalServerError, "Failed to provide jwt ")
		return
	}

	tokenResponse := struct {
		Token string `json:"token"`
	}{
		Token: JWTToken,
	}

	respondWithJSON(w, http.StatusOK, tokenResponse)
	return
}

func (cfg *apiConfig) revoke(w http.ResponseWriter, req *http.Request) {
	authHeader := req.Header.Get("Authorization")

	if len(authHeader) < 1 {
		fmt.Printf("ERROR: failed to get refresh token in headers")
		respondWithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	refreshToken := strings.Split(authHeader, " ")[1]

	if len(refreshToken) < 1 {
		fmt.Printf("ERROR: failed to get refresh token in headers instead got %v\n", refreshToken)
		respondWithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	err := cfg.dbQueries.RevokeRefreshToken(req.Context(), refreshToken)

	if err != nil {
		fmt.Printf("FATAL: failed to revoke refresh token %v\n", err.Error())
		respondWithError(w, http.StatusUnauthorized, "could not revoke refresh token")
		return

	}

	respondWithJSON(w, http.StatusNoContent, nil)

	return
}

func (cfg *apiConfig) createUsers(w http.ResponseWriter, req *http.Request) {
	type Params struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	decoder := json.NewDecoder(req.Body)
	params := &Params{}

	err := decoder.Decode(params)

	if err != nil {
		fmt.Printf("Failed to decode params -> %v", err.Error())
		respondWithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	email := params.Email
	password := params.Password
	if strings.TrimSpace(password) == "" || strings.TrimSpace(email) == "" {
		respondWithError(w, http.StatusBadRequest, "password or email should not be blank")
		return
	}

	hash, err := auth.HashPassword(params.Password)

	if err != nil {
		fmt.Printf("User creation failed error -> %v", err.Error())
		respondWithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	user, err := cfg.dbQueries.CreateUser(req.Context(), database.CreateUserParams{
		Email:          email,
		HashedPassword: hash,
	})

	if err != nil {
		fmt.Printf("User creation failed error -> %v", err.Error())
		respondWithError(w, http.StatusInternalServerError, "user creation failed")
		return
	}

	respondWithJSON(w, http.StatusCreated, user)
	return
}

func (cfg *apiConfig) updateUser(w http.ResponseWriter, req *http.Request) {
	authToken, err := auth.GetBearerToken(req.Header)

	if err != nil {
		fmt.Printf("FATAL:%v\n", err.Error())
		respondWithError(w, http.StatusUnauthorized, "Something went wrong")
		return
	}

	userID, err := auth.ValidateJWT(authToken, cfg.JWTSecret)

	if err != nil {
		fmt.Printf("ERROR:%v\n", err.Error())
		respondWithError(w, http.StatusUnauthorized, "Invalid token")
		return
	}

	type Params struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	decoder := json.NewDecoder(req.Body)

	params := &Params{}

	err = decoder.Decode(params)

	if err != nil {
		fmt.Printf("FATAL:%v\n", err.Error())
		respondWithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	hashedPassword, err := auth.HashPassword(params.Password)

	if err != nil {
		fmt.Printf("ERROR: password hashing failed %v\n", err.Error())
		respondWithError(w, http.StatusBadRequest, "could not update  password")
		return
	}

	updatedUser, err := cfg.dbQueries.UpdateUserCredentials(req.Context(), database.UpdateUserCredentialsParams{
		HashedPassword: hashedPassword,
		Email:          params.Email,
		ID:             userID,
	})
	respondWithJSON(w, http.StatusOK, updatedUser)
	return
}

func (cfg *apiConfig) deleteChirp(w http.ResponseWriter, req *http.Request) {
	authToken, err := auth.GetBearerToken(req.Header)

	if err != nil {
		fmt.Printf("FATAL:%v\n", err.Error())
		respondWithError(w, http.StatusForbidden, "Something went wrong")
		return
	}

	userID, err := auth.ValidateJWT(authToken, cfg.JWTSecret)

	if err != nil {
		fmt.Printf("ERROR:%v\n", err.Error())
		respondWithError(w, http.StatusForbidden, "user is unauthorized")
		return
	}

	chirpID := req.PathValue("chirpID")

	chirpUUID, err := uuid.Parse(chirpID)
	if err != nil {
		fmt.Printf("FATAL:%v\n", err.Error())
		respondWithError(w, http.StatusNotFound, "Something went wrong")
		return
	}

	err = cfg.dbQueries.DeleteChirp(req.Context(), database.DeleteChirpParams{
		ID: chirpUUID,
		UserID: uuid.NullUUID{
			UUID:  userID,
			Valid: true,
		},
	})

	if err != nil {
		fmt.Printf("FATAL:%v\n", err.Error())
		respondWithError(w, http.StatusNotFound, "Something went wrong")
		return
	}

	respondWithJSON(w, http.StatusNoContent, nil)

	return

}

func respondWithError(w http.ResponseWriter, code int, msg string) {
	reqError := reqError{

		Error: msg,
	}
	data, err := json.Marshal(reqError)
	w.WriteHeader(code)
	if err != nil {
		log.Printf("Could not marshal request error: %v\n", err.Error())
		w.Write(data)
		return
	}

	w.Write(data)
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {

	if code == http.StatusNoContent {
		w.WriteHeader(code)
		return
	}

	data, err := json.Marshal(payload)

	if err != nil {
		log.Printf("Could not marshal request error: %v\n", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		w.Write(data)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(data)

	return
}
