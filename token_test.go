package token

import (
	"encoding/base64"
	"fmt"

	"testing"
	"time"
)

var (
	secret = "secretForTesting"
	id     = "12345678"
)

func TestValidToken(t *testing.T) {
	g := NewTokenHmacSha(secret)
	token := g.Generate(id)

	t.Log("Token Generated ", token)

	valid, actualId, issue := g.Valid(token, 10*time.Minute)
	if !valid {
		t.Error("Token is not valid: Expected to be valid")
	}
	if actualId != id {
		t.Errorf("Id is not the same, %v != %v", actualId, id)
	}
	t.Logf("Token Valid=%v Id=%v Issue=%v", valid, actualId, issue)
}

func TestValidAndNotExpiredToken(t *testing.T) {
	g := NewTokenHmacSha(secret)
	token := g.Generate(id)

	t.Log("Token Generated ", token)

	time.Sleep(100 * time.Millisecond)
	valid, actualId, issue := g.Valid(token, 10*time.Minute)
	if !valid {
		t.Error("Token is not valid: Expected to be valid")
	}

	valid, actualId, issue = g.Valid(token, 1*time.Second)
	if !valid {
		t.Error("Token is not valid: Expected to be valid")
	}
	t.Logf("Token Valid=%v Id=%v Issue=%v", valid, actualId, issue)

	valid, actualId, issue = g.Valid(token, 50*time.Millisecond)
	if valid {
		t.Error("Token should be invalid!!")
	}
	t.Logf("Token Valid=%v Id=%v Issue=%v", valid, actualId, issue)
}

func TestInvalidEncode(t *testing.T) {
	g := NewTokenHmacSha(secret)
	token := "badData"

	valid, _, _ := g.Valid(token, 10*time.Minute)
	if valid {
		t.Error("Token is valid: Expected not valid, because bad encoding")
	}

}

func TestInvalidFormatEncode(t *testing.T) {
	g := NewTokenHmacSha(secret)
	raw := "badstring"

	token := base64.URLEncoding.EncodeToString([]byte(raw))

	valid, _, _ := g.Valid(token, 10*time.Minute)
	if valid {
		t.Error("Token is valid: Expected not valid, because bad format")
	}
}

func TestInvalidTimestamp(t *testing.T) {
	g := NewTokenHmacSha(secret)

	hash := base64.URLEncoding.EncodeToString([]byte("test"))
	rnd := base64.URLEncoding.EncodeToString([]byte("test1"))
	ts := base64.URLEncoding.EncodeToString([]byte("badtime"))

	token := fmt.Sprintf("%s.%s.%s.%s", hash, rnd, id, ts)

	valid, _, _ := g.Valid(token, 10*time.Minute)
	if valid {
		t.Error("Token is valid: Expected not valid, because bad timestamp")
	}
}
