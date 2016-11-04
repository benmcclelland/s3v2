# s3v2
v2 auth signer for s3 for use with aws-go-sdk

Add v2 signer to go sdk by passing this new signer like:
```go
svc := s3.New(...)
svc.Handlers.Sign.Clear()
svc.Handlers.Sign.PushBackNamed(s3v2.SignRequestHandler)
```
