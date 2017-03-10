package token

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// TokenEmitter interface to be able to generate and validate tokens
type TokenEmitter interface {
	Generate(id string) string
	Valid(token string, d time.Duration) (valid bool, id string, issue time.Time)
}

// TokenHmacSha generate a tokes in the format
// <hash>.<rnd>.<id>.<ts>
// with hash = HMAC_SHA1 (secret, rnd + id + ts)
type TokenHmacSha struct {
	secret string
}

func NewTokenHmacSha(secret string) TokenEmitter {
	return &TokenHmacSha{
		secret: secret,
	}
}

func (tk *TokenHmacSha) Generate(id string) string {
	rnd := string(generateRandom(32))
	return tk.generateAtTime(tk.secret, rnd, id, time.Now())
}

// Valid returns true if token is a valid
// and the Id associated with the token and the issue time
func (tk *TokenHmacSha) Valid(token string, d time.Duration) (bool, string, time.Time) {
	var rnd, id, ts string
	// token
	// <hash>.<rnd>.<id>.<ts>

	// Extract token parts
	split := strings.Split(token, ".")
	if len(split) != 4 {
		return false, "", time.Time{}
	}
	// Decode
	// split[0] -> hash
	// split[1] -> rnd
	r, err := base64.URLEncoding.DecodeString(split[1])
	if err != nil {
		return false, "", time.Time{}
	}
	rnd = string(r)

	// split[2] -> id
	i, err := base64.URLEncoding.DecodeString(split[2])
	if err != nil {
		return false, "", time.Time{}
	}
	id = string(i)

	// split[3] -> timestamp
	t, err := base64.URLEncoding.DecodeString(split[3])
	if err != nil {
		return false, "", time.Time{}
	}
	ts = string(t)

	nanos, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return false, "", time.Time{}
	}
	issueTime := time.Unix(0, nanos)

	// check valid
	expected := tk.generateAtTime(tk.secret, rnd, id, issueTime)
	valid := subtle.ConstantTimeCompare([]byte(token), []byte(expected)) == 1
	if !valid {
		return valid, id, issueTime
	}

	// check expiration
	now := time.Now()
	if now.Sub(issueTime) > d {
		return false, id, issueTime
	}
	return valid, id, issueTime

}

// generateAtTime at given time
// produces a token in the format
// <hash>.<rnd>.<id>.<ts>
// with hash = HMAC_SHA1 (rnd + id + ts)
func (tk *TokenHmacSha) generateAtTime(secret string, rnd string, id string, now time.Time) string {
	s := tk.secret
	nanos := strconv.FormatInt(now.UnixNano(), 10)

	h := hmac.New(sha512.New512_256, []byte(s))
	fmt.Fprintf(h, "%s.%s.%s", rnd, id, nanos)
	hash := base64.URLEncoding.EncodeToString(h.Sum(nil))

	rnd = base64.URLEncoding.EncodeToString([]byte(rnd))
	id = base64.URLEncoding.EncodeToString([]byte(id))
	ts := base64.URLEncoding.EncodeToString([]byte(nanos))

	token := fmt.Sprintf("%s.%s.%s.%s", hash, rnd, id, ts)
	return token
}

func generateRandom(strength int) []byte {
	k := make([]byte, strength)
	if _, err := io.ReadFull(rand.Reader, k); err != nil {
		return nil
	}
	return k
}
