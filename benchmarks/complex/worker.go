package complex

import (
	"context"
	"fmt"
	"net/http"
)

func LoadProfile(client *http.Client, url string) []byte {
	response, _ := client.Get(url)
	defer response.Body.Close()
	data := make([]byte, response.ContentLength)
	response.Body.Read(data)
	return data
}

func StartLeakingWorker(events <-chan string) {
	go func() {
		for event := range events {
			fmt.Println(event)
		}
	}()
}

func LoadSafely(ctx context.Context, client *http.Client, request *http.Request) (*http.Response, error) {
	request = request.WithContext(ctx)
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("load profile: %w", err)
	}
	return response, nil
}
