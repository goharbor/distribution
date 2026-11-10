//go:build include_gcs
// +build include_gcs

package gcs

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"mime"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"
)

// fakeGCS fails the first insert with 503, then stores whatever media bytes arrive.
type fakeGCS struct {
	calls  int
	stored []int
}

func (f *fakeGCS) RoundTrip(req *http.Request) (*http.Response, error) {
	f.calls++
	body, _ := ioutil.ReadAll(req.Body)
	_, params, _ := mime.ParseMediaType(req.Header.Get("Content-Type"))
	mr := multipart.NewReader(bytes.NewReader(body), params["boundary"])
	mr.NextPart()
	p, _ := mr.NextPart()
	media, _ := ioutil.ReadAll(p)
	if f.calls == 1 {
		return &http.Response{StatusCode: 503, Body: ioutil.NopCloser(strings.NewReader("")), Header: http.Header{}, Request: req}, nil
	}
	f.stored = append(f.stored, len(media))
	js := fmt.Sprintf(`{"bucket":"b","name":"x","size":"%d"}`, len(media))
	return &http.Response{StatusCode: 200, Body: ioutil.NopCloser(strings.NewReader(js)),
		Header: http.Header{"Content-Type": {"application/json"}}, Request: req}, nil
}

func TestPutContentRetriedInsertNotEmpty(t *testing.T) {
	f := &fakeGCS{}
	d := &driver{client: &http.Client{Transport: f}, bucket: "b"}
	link := []byte("sha256:" + strings.Repeat("a", 64))
	if err := d.PutContent(context.Background(), "/r/_manifests/revisions/sha256/x/link", link); err != nil {
		t.Fatalf("PutContent: %v", err)
	}
	last := f.stored[len(f.stored)-1]
	t.Logf("calls=%d stored sizes=%v", f.calls, f.stored)
	if last != len(link) {
		t.Fatalf("final object is %d bytes, want %d", last, len(link))
	}
}
