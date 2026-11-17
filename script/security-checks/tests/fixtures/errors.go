package fixtures

import (
	"errors"
	"fmt"
	"net/http"
	"runtime/debug"
)

func messages(w http.ResponseWriter, err error) error {
	// ruleid: go-error-message-text
	_ = errors.New("Contact Support")
	// ruleid: go-error-message-text
	_ = fmt.Errorf("Failed to create cluster: verify the network and retry: %w", err)
	// ruleid: go-error-message-text
	http.Error(w, "Invalid port: set a value from 1 to 65535 and retry", 400)
	// ruleid: go-raw-error-http-response
	http.Error(w, err.Error(), 500)
	// ruleid: go-raw-error-http-response
	http.Error(w, string(debug.Stack()), 500)
	// ruleid: go-raw-stack-output
	debug.PrintStack()
	// ruleid: go-swallowed-error
	if err != nil {
		return nil
	}
	// ok: go-swallowed-error
	if err != nil {
		return err
	}
	return nil
}

var descriptor = struct{ Message string }{
	// ruleid: go-error-message-text
	Message: "Deployment failed: check the configured DNS server and retry",
}
