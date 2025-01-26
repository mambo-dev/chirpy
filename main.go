package main

import "net/http"

func main() {
	mux := http.NewServeMux()
	server := &http.Server{
		Handler: mux,
		Addr:    ":8080",
	}

	mux.HandleFunc("/healthz", ok)

	mux.Handle("/app/", http.StripPrefix("/", http.FileServer(http.Dir("."))))
	server.ListenAndServe()

}

func ok(w http.ResponseWriter, req *http.Request) {

	req.Header.Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))

}
