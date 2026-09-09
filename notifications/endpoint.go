package notifications

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/docker/distribution/configuration"
)

// EndpointConfig covers the optional configuration parameters for an active
// endpoint.
type EndpointConfig struct {
	Headers           http.Header
	Timeout           time.Duration
	Threshold         int
	Backoff           time.Duration
	IgnoredMediaTypes []string
	Transport         *http.Transport `json:"-"`
	Ignore            configuration.Ignore
}

// defaults set any zero-valued fields to a reasonable default.
func (ec *EndpointConfig) defaults() {
	if ec.Timeout <= 0 {
		ec.Timeout = time.Second
	}

	if ec.Threshold <= 0 {
		ec.Threshold = 10
	}

	if ec.Backoff <= 0 {
		ec.Backoff = time.Second
	}

	if ec.Transport == nil {
		ec.Transport = http.DefaultTransport.(*http.Transport)
	}
}

// Endpoint is a reliable, queued, thread-safe sink that notify external http
// services when events are written. Writes are non-blocking and always
// succeed for callers but events may be queued internally.
type Endpoint struct {
	Sink
	url  string
	name string

	EndpointConfig

	metrics *safeMetrics
}

// NewEndpoint returns a running endpoint, ready to receive events.
func NewEndpoint(name, url string, config EndpointConfig) *Endpoint {
	var endpoint Endpoint
	endpoint.name = name
	endpoint.url = url
	endpoint.EndpointConfig = config
	endpoint.defaults()
	endpoint.metrics = newSafeMetrics()

	// Configures the inmemory queue, retry, http pipeline.
	endpoint.Sink = newHTTPSink(
		endpoint.url, endpoint.Timeout, endpoint.Headers,
		endpoint.Transport, endpoint.metrics.httpStatusListener())
	endpoint.Sink = newRetryingSink(endpoint.Sink, endpoint.Threshold, endpoint.Backoff)
	endpoint.Sink = newEventQueue(endpoint.Sink, endpoint.metrics.eventQueueListener())
	mediaTypes := append(config.Ignore.MediaTypes, config.IgnoredMediaTypes...)
	endpoint.Sink = newIgnoredSink(endpoint.Sink, mediaTypes, config.Ignore.Actions)

	register(&endpoint)
	return &endpoint
}

// Name returns the name of the endpoint, generally used for debugging.
func (e *Endpoint) Name() string {
	return e.name
}

// URL returns the url of the endpoint.
func (e *Endpoint) URL() string {
	return e.url
}

// SanitizeHeaders returns a copy of http.Header with sensitive values redacted.
func SanitizeHeaders(headers http.Header) http.Header {
	if headers == nil {
		return nil
	}
	sanitizedHeaders := make(http.Header, len(headers))
	for k, v := range headers {
		lowerK := strings.ToLower(k)
		if strings.EqualFold(k, "Authorization") ||
			strings.EqualFold(k, "Proxy-Authorization") ||
			strings.EqualFold(k, "Cookie") ||
			strings.EqualFold(k, "Set-Cookie") ||
			strings.Contains(lowerK, "token") ||
			strings.Contains(lowerK, "secret") ||
			strings.Contains(lowerK, "password") ||
			strings.Contains(lowerK, "key") {
			sanitizedHeaders[k] = []string{"********"}
		} else {
			sanitizedHeaders[k] = v
		}
	}
	return sanitizedHeaders
}

// SanitizeURL returns a URL string with sensitive userinfo credentials redacted.
func SanitizeURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	if u.User != nil {
		if _, hasPassword := u.User.Password(); hasPassword {
			return u.Redacted()
		}
		u.User = url.User("xxxxx")
	}
	return u.String()
}

// ReadMetrics populates em with metrics from the endpoint.
func (e *Endpoint) ReadMetrics(em *EndpointMetrics) {
	e.metrics.Lock()
	defer e.metrics.Unlock()

	*em = e.metrics.EndpointMetrics
	// Map still need to copied in a threadsafe manner.
	em.Statuses = make(map[string]int)
	for k, v := range e.metrics.Statuses {
		em.Statuses[k] = v
	}
}
