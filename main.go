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

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"github.com/mambo-dev/chirpy/internal/auth"
	"github.com/mambo-dev/chirpy/internal/database"
)

func main() {
	godotenv.Load()
	dbURL := os.Getenv("DB_URL")
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
	apiConfig.dbQueries = dbQueries
	mux.HandleFunc("GET /api/healthz", ok)

	mux.HandleFunc("GET /api/chirps/{chirpID}", apiConfig.getChirp)
	mux.HandleFunc("GET /api/chirps", apiConfig.getChirps)
	mux.HandleFunc("POST /api/chirps", apiConfig.createChirp)
	mux.HandleFunc("POST /api/users", apiConfig.createUsers)
	mux.HandleFunc("POST /api/login", apiConfig.login)
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
		Body   string    `json:"body"`
		UserID uuid.UUID `json:"user_id"`
	}

	decoder := json.NewDecoder(req.Body)
	params := &Params{}

	err := decoder.Decode(params)

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
			UUID:  params.UserID,
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

	return http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		cfg.fileserverHits.Add(1)

		next.ServeHTTP(responseWriter, request)
	})
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

		respondWithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}
	email := params.Email

	user, err := cfg.dbQueries.GetUserByEmail(req.Context(), email)

	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Incorrect email or password")
		return
	}

	err = auth.CheckPasswordHash(user.HashedPassword, params.Password)

	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Incorrect email or password")
		return
	}

	respondWithJSON(w, http.StatusOK, user)
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
		respondWithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	user, err := cfg.dbQueries.CreateUser(req.Context(), database.CreateUserParams{
		Email:          email,
		HashedPassword: hash,
	})

	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "user creation failed")
		return
	}

	respondWithJSON(w, http.StatusCreated, user)
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
