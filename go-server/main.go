package main

import (
	"encoding/json"
	"log"
	"net/http"
	"vulnora/go-server/loadtest"
)

type TestRequest struct {
	URL       string `json:"url"`
	Duration  int    `json:"duration"`  // in seconds
	Threads   int    `json:"threads"`   // mention no. of threads to use
	RateLimit int    `json:"rateLimit"` // requests per second per thread
}

func main() {
	http.HandleFunc("/run-test", func(w http.ResponseWriter, r *http.Request) {
		var req TestRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid input", http.StatusBadRequest)
			return
		}

		result := loadtest.RunLoadTest(req.URL, req.Duration, req.Threads, req.RateLimit)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	})

	log.Println("Server running on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
