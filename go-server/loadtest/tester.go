package loadtest

import (
	"net/http"
	"sync"
	"time"
)

type Result struct {
	TotalRequests int           `json:"total_requests"`
	SuccessCount  int           `json:"success_count"`
	FailureCount  int           `json:"failure_count"`
	AvgLatency    time.Duration `json:"avg_latency"`
}

func RunLoadTest(url string, duration, threads, rateLimit int) Result {
	var success, failure int
	var latencySum time.Duration
	var mu sync.Mutex
	var wg sync.WaitGroup

	endTime := time.Now().Add(time.Duration(duration) * time.Second)

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client := &http.Client{}
			ticker := time.NewTicker(time.Second / time.Duration(rateLimit))
			defer ticker.Stop()

			for time.Now().Before(endTime) {
				<-ticker.C
				start := time.Now()
				resp, err := client.Get(url)
				elapsed := time.Since(start)

				mu.Lock()
				if err != nil || resp.StatusCode >= 400 {
					failure++
				} else {
					success++
					latencySum += elapsed
				}
				mu.Unlock()

				if resp != nil {
					resp.Body.Close()
				}
			}
		}()
	}

	wg.Wait()
	total := success + failure
	avgLatency := time.Duration(0)
	if success > 0 {
		avgLatency = latencySum / time.Duration(success)
	}
	return Result{
		TotalRequests: total,
		SuccessCount:  success,
		FailureCount:  failure,
		AvgLatency:    avgLatency,
	}
}