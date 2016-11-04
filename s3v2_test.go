package s3v2

import (
	"net/http"
	"net/url"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/stretchr/testify/assert"
)

type signerBuilder struct {
	Region       string
	Method       string
	SessionToken string
	Endpoint     string
	Query        url.Values
}

func (sb signerBuilder) BuildSigner() signer {
	req, _ := http.NewRequest(sb.Method, sb.Endpoint, nil)

	sig := signer{
		Request: req,
		Credentials: credentials.NewStaticCredentials(
			"AKIAIOSFODNN7EXAMPLE",
			"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			sb.SessionToken),
		Query: sb.Query,
	}

	for k, values := range sb.Query {
		for _, v := range values {
			sig.Request.Header.Add(k, v)
		}
	}

	if os.Getenv("DEBUG") != "" {
		sig.Debug = aws.LogDebug
		sig.Logger = aws.NewDefaultLogger()
	}

	return sig
}

// Following test cases are taken from
// http://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html
// More test coverage is needed for:
// - pathsyle
// - security token
// - Query String Request Authentication (missing, needed?)

func TestSignRequestGET(t *testing.T) {
	assert := assert.New(t)

	uri := "https://johnsmith.s3.amazonaws.com/photos/puppy.jpg"

	newQuery := func() url.Values {
		query := make(url.Values)
		query.Add("Date", "Tue, 27 Mar 2007 19:36:42 +0000")
		query.Add("GET", uri)
		query.Add("Host", "johnsmith.s3.amazonaws.com")
		return query
	}

	query := newQuery()

	builder := signerBuilder{
		Method:   "GET",
		Endpoint: uri,
		Query:    query,
	}

	signer := builder.BuildSigner()
	signer.Request.URL.Path = "/photos/puppy.jpg"
	signer.Request.URL.Opaque = "//johnsmith.s3.amazonaws.com/photos/puppy.jpg"

	err := signer.Sign()
	assert.NoError(err)
	assert.Equal("bWq2s1WEIj+Ydj0vQ697zp+IXMU=", signer.signature)
	assert.Equal("/johnsmith/photos/puppy.jpg", signer.canonicalResource)
	assert.Equal("", signer.canonicalAmzHeaders)
	assert.Equal("GET\n\n\nTue, 27 Mar 2007 19:36:42 +0000\n/johnsmith/photos/puppy.jpg", signer.stringToSign)
	assert.Equal("AWS AKIAIOSFODNN7EXAMPLE:bWq2s1WEIj+Ydj0vQ697zp+IXMU=", signer.Query.Get("Authorization"))

	// should not have a SecurityToken parameter
	_, ok := signer.Query["SecurityToken"]
	assert.False(ok)
}

func TestSignRequestPUT(t *testing.T) {
	assert := assert.New(t)

	uri := "https://johnsmith.s3.amazonaws.com/photos/puppy.jpg"

	newQuery := func() url.Values {
		query := make(url.Values)
		query.Add("Date", "Tue, 27 Mar 2007 21:15:45 +0000")
		query.Add("PUT", uri)
		query.Add("Content-Type", "image/jpeg")
		query.Add("Content-Length", "94328")
		query.Add("Host", "johnsmith.s3.amazonaws.com")
		return query
	}

	query := newQuery()

	builder := signerBuilder{
		Method:   "PUT",
		Endpoint: uri,
		Query:    query,
	}

	signer := builder.BuildSigner()
	signer.Request.URL.Path = "/photos/puppy.jpg"

	err := signer.Sign()
	assert.NoError(err)
	assert.Equal("MyyxeRY7whkBe+bq8fHCL/2kKUg=", signer.signature)
	assert.Equal("/johnsmith/photos/puppy.jpg", signer.canonicalResource)
	assert.Equal("", signer.canonicalAmzHeaders)
	assert.Equal("PUT\n\nimage/jpeg\nTue, 27 Mar 2007 21:15:45 +0000\n/johnsmith/photos/puppy.jpg", signer.stringToSign)
	assert.Equal("AWS AKIAIOSFODNN7EXAMPLE:MyyxeRY7whkBe+bq8fHCL/2kKUg=", signer.Query.Get("Authorization"))

	// should not have a SecurityToken parameter
	_, ok := signer.Query["SecurityToken"]
	assert.False(ok)
}

func TestSignRequestList(t *testing.T) {
	assert := assert.New(t)

	uri := "https://johnsmith.s3.amazonaws.com/?prefix=photos&max-keys=50&marker=puppy"

	newQuery := func() url.Values {
		query := make(url.Values)
		query.Add("Date", "Tue, 27 Mar 2007 19:42:41 +0000")
		query.Add("GET", uri)
		query.Add("Host", "johnsmith.s3.amazonaws.com")
		return query
	}

	query := newQuery()

	builder := signerBuilder{
		Method:   "GET",
		Endpoint: uri,
		Query:    query,
	}

	signer := builder.BuildSigner()
	signer.Request.URL.Path = "/"

	err := signer.Sign()
	assert.NoError(err)
	assert.Equal("htDYFYduRNen8P9ZfE/s9SuKy0U=", signer.signature)
	assert.Equal("/johnsmith/", signer.canonicalResource)
	assert.Equal("", signer.canonicalAmzHeaders)
	assert.Equal("GET\n\n\nTue, 27 Mar 2007 19:42:41 +0000\n/johnsmith/", signer.stringToSign)
	assert.Equal("AWS AKIAIOSFODNN7EXAMPLE:htDYFYduRNen8P9ZfE/s9SuKy0U=", signer.Query.Get("Authorization"))

	// should not have a SecurityToken parameter
	_, ok := signer.Query["SecurityToken"]
	assert.False(ok)
}

func TestSignRequestFetch(t *testing.T) {
	assert := assert.New(t)

	uri := "https://johnsmith.s3.amazonaws.com/?acl"

	newQuery := func() url.Values {
		query := make(url.Values)
		query.Add("Date", "Tue, 27 Mar 2007 19:44:46 +0000")
		query.Add("GET", uri)
		query.Add("Host", "johnsmith.s3.amazonaws.com")
		return query
	}

	query := newQuery()

	builder := signerBuilder{
		Method:   "GET",
		Endpoint: uri,
		Query:    query,
	}

	signer := builder.BuildSigner()
	signer.Request.URL.Path = "/"

	err := signer.Sign()
	assert.NoError(err)
	assert.Equal("c2WLPFtWHVgbEmeEG93a4cG37dM=", signer.signature)
	assert.Equal("/johnsmith/?acl", signer.canonicalResource)
	assert.Equal("", signer.canonicalAmzHeaders)
	assert.Equal("GET\n\n\nTue, 27 Mar 2007 19:44:46 +0000\n/johnsmith/?acl", signer.stringToSign)
	assert.Equal("AWS AKIAIOSFODNN7EXAMPLE:c2WLPFtWHVgbEmeEG93a4cG37dM=", signer.Query.Get("Authorization"))

	// should not have a SecurityToken parameter
	_, ok := signer.Query["SecurityToken"]
	assert.False(ok)
}

func TestSignRequestDelete(t *testing.T) {
	assert := assert.New(t)

	uri := "https://johnsmith.s3.amazonaws.com/photos/puppy.jpg"

	newQuery := func() url.Values {
		query := make(url.Values)
		query.Add("Date", "Tue, 27 Mar 2007 21:20:26 +0000")
		query.Add("DELETE", uri)
		query.Add("Host", "johnsmith.s3.amazonaws.com")
		return query
	}

	query := newQuery()

	builder := signerBuilder{
		Method:   "DELETE",
		Endpoint: uri,
		Query:    query,
	}

	signer := builder.BuildSigner()
	signer.Request.URL.Path = "/photos/puppy.jpg"

	err := signer.Sign()
	assert.NoError(err)
	assert.Equal("lx3byBScXR6KzyMaifNkardMwNk=", signer.signature)
	assert.Equal("/johnsmith/photos/puppy.jpg", signer.canonicalResource)
	assert.Equal("", signer.canonicalAmzHeaders)
	assert.Equal("DELETE\n\n\nTue, 27 Mar 2007 21:20:26 +0000\n/johnsmith/photos/puppy.jpg", signer.stringToSign)
	assert.Equal("AWS AKIAIOSFODNN7EXAMPLE:lx3byBScXR6KzyMaifNkardMwNk=", signer.Query.Get("Authorization"))

	// should not have a SecurityToken parameter
	_, ok := signer.Query["SecurityToken"]
	assert.False(ok)
}

func TestSignRequestUpload(t *testing.T) {
	assert := assert.New(t)

	uri := "https://static.johnsmith.net:8080/static.johnsmith.net/db-backup.dat.gz"

	newQuery := func() url.Values {
		query := make(url.Values)
		query.Add("Date", "Tue, 27 Mar 2007 21:06:08 +0000")
		query.Add("PUT", uri)
		query.Add("Host", "static.johnsmith.net:8080")
		query.Add("x-amz-acl", "public-read")
		query.Add("content-type", "application/x-download")
		query.Add("Content-MD5", "4gJE4saaMU4BqNR0kLY+lw==")
		query.Add("X-Amz-Meta-ReviewedBy", "joe@johnsmith.net")
		query.Add("X-Amz-Meta-ReviewedBy", "jane@johnsmith.net")
		query.Add("X-Amz-Meta-FileChecksum", "0x02661779")
		query.Add("X-Amz-Meta-ChecksumAlgorithm", "crc32")
		query.Add("Content-Disposition", "attachment; filename=database.dat")
		query.Add("Content-Encoding", "gzip")
		query.Add("Content-Length", "5913339")
		return query
	}

	query := newQuery()

	builder := signerBuilder{
		Method:   "PUT",
		Endpoint: uri,
		Query:    query,
	}

	signer := builder.BuildSigner()
	signer.Request.URL.Path = "/static.johnsmith.net/db-backup.dat.gz"

	err := signer.Sign()
	assert.NoError(err)
	assert.Equal("ilyl83RwaSoYIEdixDQcA4OnAnc=", signer.signature)
	assert.Equal("/static.johnsmith.net/db-backup.dat.gz", signer.canonicalResource)
	assert.Equal("x-amz-acl:public-read\n"+
		"x-amz-meta-checksumalgorithm:crc32\n"+
		"x-amz-meta-filechecksum:0x02661779\n"+
		"x-amz-meta-reviewedby:"+
		"joe@johnsmith.net,jane@johnsmith.net\n", signer.canonicalAmzHeaders)
	assert.Equal("PUT\n"+
		"4gJE4saaMU4BqNR0kLY+lw==\n"+
		"application/x-download\n"+
		"Tue, 27 Mar 2007 21:06:08 +0000\n"+
		"x-amz-acl:public-read\n"+
		"x-amz-meta-checksumalgorithm:crc32\n"+
		"x-amz-meta-filechecksum:0x02661779\n"+
		"x-amz-meta-reviewedby:"+
		"joe@johnsmith.net,jane@johnsmith.net\n"+
		"/static.johnsmith.net/db-backup.dat.gz", signer.stringToSign)
	assert.Equal("AWS AKIAIOSFODNN7EXAMPLE:ilyl83RwaSoYIEdixDQcA4OnAnc=", signer.Query.Get("Authorization"))

	// should not have a SecurityToken parameter
	_, ok := signer.Query["SecurityToken"]
	assert.False(ok)
}

func TestSignRequestListBuckets(t *testing.T) {
	assert := assert.New(t)

	uri := "https://s3.amazonaws.com/"

	newQuery := func() url.Values {
		query := make(url.Values)
		query.Add("Date", "Wed, 28 Mar 2007 01:29:59 +0000")
		query.Add("GET", uri)
		query.Add("Host", "s3.amazonaws.com")
		return query
	}

	query := newQuery()

	builder := signerBuilder{
		Method:   "GET",
		Endpoint: uri,
		Query:    query,
	}

	signer := builder.BuildSigner()
	signer.Request.URL.Path = "/"

	err := signer.Sign()
	assert.NoError(err)
	assert.Equal("qGdzdERIC03wnaRNKh6OqZehG9s=", signer.signature)
	assert.Equal("/", signer.canonicalResource)
	assert.Equal("", signer.canonicalAmzHeaders)
	assert.Equal("GET\n"+
		"\n"+
		"\n"+
		"Wed, 28 Mar 2007 01:29:59 +0000\n"+
		"/", signer.stringToSign)
	assert.Equal("AWS AKIAIOSFODNN7EXAMPLE:qGdzdERIC03wnaRNKh6OqZehG9s=", signer.Query.Get("Authorization"))

	// should not have a SecurityToken parameter
	_, ok := signer.Query["SecurityToken"]
	assert.False(ok)
}

func TestSignRequestUnicodeKeys(t *testing.T) {
	assert := assert.New(t)

	uri := "https://s3.amazonaws.com/dictionary/fran%C3%A7ais/pr%c3%a9f%c3%a8re"

	newQuery := func() url.Values {
		query := make(url.Values)
		query.Add("Date", "Wed, 28 Mar 2007 01:49:49 +0000")
		query.Add("GET", uri)
		query.Add("Host", "s3.amazonaws.com")
		return query
	}

	query := newQuery()

	builder := signerBuilder{
		Method:   "GET",
		Endpoint: uri,
		Query:    query,
	}

	signer := builder.BuildSigner()
	signer.Request.URL.Path = "/dictionary/fran%C3%A7ais/pr%c3%a9f%c3%a8re"

	err := signer.Sign()
	assert.NoError(err)
	assert.Equal("DNEZGsoieTZ92F3bUfSPQcbGmlM=", signer.signature)
	assert.Equal("/dictionary/fran%C3%A7ais/pr%c3%a9f%c3%a8re", signer.canonicalResource)
	assert.Equal("", signer.canonicalAmzHeaders)
	assert.Equal("GET\n"+
		"\n"+
		"\n"+
		"Wed, 28 Mar 2007 01:49:49 +0000\n"+
		"/dictionary/fran%C3%A7ais/pr%c3%a9f%c3%a8re", signer.stringToSign)
	assert.Equal("AWS AKIAIOSFODNN7EXAMPLE:DNEZGsoieTZ92F3bUfSPQcbGmlM=", signer.Query.Get("Authorization"))

	// should not have a SecurityToken parameter
	_, ok := signer.Query["SecurityToken"]
	assert.False(ok)
}
