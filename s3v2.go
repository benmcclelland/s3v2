package s3v2

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/request"
)

const (
	signatureVersion = "2"
	signatureMethod  = "HmacSHA1"
	timeFormat       = time.RFC1123Z
)

type signer struct {
	// Values that must be populated from the request
	Request     *http.Request
	Time        time.Time
	Credentials *credentials.Credentials
	Debug       aws.LogLevelType
	Logger      aws.Logger
	Query       url.Values
	PathStyle   bool

	canonicalResource   string
	canonicalAmzHeaders string
	stringToSign        string
	signature           string
}

// SignRequestHandler is a named request handler the SDK will use to sign
// service client request with using the V2 signature.
var SignRequestHandler = request.NamedHandler{
	Name: "v2.SignRequestHandler", Fn: SignSDKRequest,
}

// SignSDKRequest requests with signature version 2.
//
// Will sign the requests with the service config's Credentials object
// Signing is skipped if the credentials is the credentials.AnonymousCredentials
// object.
//
// This is intended to be specific to S3, for others use v2 or v4
func SignSDKRequest(req *request.Request) {
	// If the request does not need to be signed ignore the signing of the
	// request if the AnonymousCredentials object is used.
	if req.Config.Credentials == credentials.AnonymousCredentials {
		return
	}

	v2 := signer{
		Request:     req.HTTPRequest,
		Credentials: req.Config.Credentials,
		Debug:       req.Config.LogLevel.Value(),
		Logger:      req.Config.Logger,
		Query:       req.HTTPRequest.URL.Query(),
		PathStyle:   *req.Config.S3ForcePathStyle,
	}

	req.HTTPRequest.Header.Del("Authorization")
	req.Error = v2.Sign()

	if req.Error != nil {
		return
	}

	req.HTTPRequest.Header.Add("Authorization", v2.Query.Get("Authorization"))
	if req.HTTPRequest.Header.Get("Date") == "" {
		req.HTTPRequest.Header.Set("Date", v2.Query.Get("Date"))
	}
}

// Sign the request
func (v2 *signer) Sign() error {
	credValue, err := v2.Credentials.Get()
	if err != nil {
		return err
	}

	// in case this is a retry, ensure no signature present
	v2.Query.Del("Authorization")

	method := v2.Request.Method
	md5 := v2.Request.Header.Get("Content-Md5")
	contentType := v2.Request.Header.Get("Content-Type")

	if v2.Request.Header.Get("Date") == "" {
		v2.Request.Header.Set("Date", time.Now().UTC().Format(timeFormat))
	}
	date := v2.Request.Header.Get("Date")

	v2.buildCanonicalizedResource()
	v2.buildCanonicalizedAmzHeaders()

	// build the canonical string for the V2 signature
	v2.stringToSign = strings.Join([]string{
		method,
		md5,
		contentType,
		date,
	}, "\n")
	v2.stringToSign += "\n"
	v2.stringToSign += v2.canonicalAmzHeaders
	v2.stringToSign += v2.canonicalResource

	hash := hmac.New(sha1.New, []byte(credValue.SecretAccessKey))
	hash.Write([]byte(v2.stringToSign))
	v2.signature = base64.StdEncoding.EncodeToString(hash.Sum(nil))
	//v2.Query.Set("Signature", v2.signature)
	v2.Query.Set("Authorization", "AWS "+credValue.AccessKeyID+":"+v2.signature)

	if v2.Debug.Matches(aws.LogDebugWithSigning) {
		v2.logSigningInfo()
	}

	return nil
}

func (v2 *signer) buildCanonicalizedResource() {
	// This is terrible, but host and path seem to never bet set,
	// so we are always going back to the opaque to figure these out
	// better way?  must be?
	if v2.Request.Host == "" {
		v2.Request.Host = strings.Split(v2.Request.URL.Opaque, "/")[2]
	}
	if v2.Request.URL.Path == "" {
		v2.Request.URL.Path = "/" + strings.Join(strings.Split(v2.Request.URL.Opaque, "/")[3:], "/")
	}

	if v2.PathStyle {
		v2.canonicalResource = v2.Request.URL.Path
	} else {
		v2.canonicalResource = ""
		// This feels fragile, find a better way
		if strings.Count(v2.Request.Host, ".") == 3 {
			v2.canonicalResource = "/" + strings.Split(v2.Request.Host, ".")[0]
		}
		v2.canonicalResource += v2.Request.URL.Path
		if v2.canonicalResource == "" {
			v2.canonicalResource = "/"
		}
	}

	first := true
	subResources := "acl,lifecycle,location,logging,notification,partNumber,policy,requestPayment,torrent,uploadId,uploads,versionId,versioning,versions,website"

	// would be better to swap these, but it appears that we need
	// to keep this in lexicographically sorted order
	// so just loop looking for the subresources we care about
	// in the correct order
	// the resources section (if there are any) always start with ?
	// after that they are separated by &
	for _, sr := range strings.Split(subResources, ",") {
		for _, reqSubResource := range strings.Split(v2.Request.URL.RawQuery, "&") {
			if strings.HasPrefix(reqSubResource, sr) {
				if first {
					v2.canonicalResource += "?"
					first = false
				} else {
					v2.canonicalResource += "&"
				}
				// ugh, multipart intiates with ?uploads=
				// but we only sign with ?uploads
				r := strings.Split(reqSubResource, "=")
				if len(r) < 2 || r[1] == "" {
					v2.canonicalResource += r[0]
				} else {
					v2.canonicalResource += reqSubResource
				}
				break
			}
		}
	}
}

func (v2 *signer) buildCanonicalizedAmzHeaders() {
	var headers []string
	lowerCaseHeaders := make(url.Values)
	for header := range v2.Request.Header {
		lowerCaseHeader := strings.ToLower(strings.TrimSpace(header))
		if strings.HasPrefix(lowerCaseHeader, "x-amz") && !stringInSlice(lowerCaseHeader, headers) {
			for _, value := range v2.Request.Header[header] {
				lowerCaseHeaders.Add(lowerCaseHeader, value)
			}
			headers = append(headers, lowerCaseHeader)
		}
	}

	sort.Strings(headers)

	for i, header := range headers {
		values := lowerCaseHeaders[header]
		for _, value := range values {
			strings.Replace(value, "\n", " ", -1)
		}
		headers[i] = header + ":" + strings.Join(values, ",")
	}

	if len(headers) > 0 {
		v2.canonicalAmzHeaders = strings.Join(headers, "\n") + "\n"
	} else {
		v2.canonicalAmzHeaders = ""
	}
}

func stringInSlice(str string, list []string) bool {
	for _, v := range list {
		if v == str {
			return true
		}
	}
	return false
}

const logSignInfoMsg = `DEBUG: Request Signature:
---[ STRING TO SIGN ]--------------------------------
%s
---[ SIGNATURE ]-------------------------------------
%s
-----------------------------------------------------`

func (v2 *signer) logSigningInfo() {
	msg := fmt.Sprintf(logSignInfoMsg, v2.stringToSign, v2.Query.Get("Authorization"))
	v2.Logger.Log(msg)
}
