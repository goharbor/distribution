package fixtures

import (
	"fmt"
	"log"
	"net/http"
	"os"
)

func logCredentials(password, apiKey string, request *http.Request) {
	// ruleid: go-secret-to-log
	log.Printf("value: %s", password)
	// ruleid: go-secret-to-log
	fmt.Println(apiKey)
	// ruleid: go-secret-to-log
	fmt.Fprintf(os.Stderr, "%s", password)
	copy := password
	// ruleid: go-secret-to-log
	log.Println(copy)
	value := request.Header.Get("Authorization")
	// ruleid: go-secret-to-log
	log.Println(value)
	// ok: go-secret-to-log
	log.Printf("password=%s", "[REDACTED]")
	// ok: go-secret-to-log
	log.Println("authentication failed; inspect the credential configuration")
}

func defaults() {
	// ruleid: go-hardcoded-secret
	password := "weak-default"
	// ruleid: go-hardcoded-secret
	const clientSecret = "default-value"
	// ok: go-hardcoded-secret
	password = os.Getenv("PASSWORD")
	// ok: go-hardcoded-secret
	password = ""
	// ok: go-hardcoded-secret
	password = "********"
}

func credentialTypeError(credentialType string) error {
	// ok: go-secret-to-log
	return fmt.Errorf("unsupported credential type: %s", credentialType)
}
