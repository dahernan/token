## Secure Token Go library to emit tokens

Usage:

Please do copy & paste the code, don't create more dependencies :)

```
// Generate token with id
tgen := token.NewTokenHmacSha(secret)
token := tgen.Generate(id)

// Check if the token is valid for a given duration
valid, id, issueTime := tgen.Valid(token, 10*time.Minute)

```
