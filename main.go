package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"

	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
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
	mux.HandleFunc("POST /api/validate_chirp", validateChirp)
	mux.HandleFunc("POST /api/users", apiConfig.createUsers)
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

func validateChirp(w http.ResponseWriter, req *http.Request) {

	type parameters struct {
		Body string `json:"body"`
	}
	decoder := json.NewDecoder(req.Body)

	params := parameters{}

	err := decoder.Decode(&params)

	if err != nil {

		respondWithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	if len(params.Body) > 140 {

		respondWithError(w, http.StatusBadRequest, "Chirp is too long")
		return
	}

	body := params.Body
	newString := []string{}
	for _, character := range strings.Split(body, " ") {
		stringCharacter := string(character)
		if strings.ToLower(stringCharacter) == "kerfuffle" || strings.ToLower(stringCharacter) == "sharbert" || strings.ToLower(stringCharacter) == "fornax" {
			newString = append(newString, "****")
		} else {
			newString = append(newString, stringCharacter)
		}
	}

	success := Success{
		CleanedBody: strings.Join(newString, " "),
	}

	respondWithJSON(w, http.StatusOK, success)

}

func (cfg *apiConfig) createUsers(w http.ResponseWriter, req *http.Request) {
	type Params struct {
		Email string `json:"email"`
	}

	decoder := json.NewDecoder(req.Body)
	params := &Params{}

	err := decoder.Decode(&params)

	if err != nil {

		respondWithError(w, http.StatusInternalServerError, "Something went wrong")
		return
	}

	email := params.Email

	user, err := cfg.dbQueries.CreateUser(req.Context(), email)

	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "user creation failed")
		return
	}

	respondWithJSON(w, http.StatusOK, user)
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
