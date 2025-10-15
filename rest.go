package sipcallmon

import (
	"crypto/tls"
	"strings"
	"time"

	"github.com/valyala/fasthttp"
)

type RESTcfg struct {
	Method       string
	ContentType  string
	XHeaders     []string // extra http headers
	MaxRedirects int
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

// RESTclient will be used to make the http requests.
// It holds the connection pool used for http connection reuse.
type RESTclient struct {
	c    *fasthttp.Client
	req  *fasthttp.Request  // re-use request if != nil (alloc only once)
	resp *fasthttp.Response // re-use reply if != nil (alloc only once)
	cfg  RESTcfg            // copy of the config used for c
}

func NewRESTclient(cfg RESTcfg) *RESTclient {
	rc := &RESTclient{
		c: &fasthttp.Client{
			TLSConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			ReadTimeout:                   cfg.ReadTimeout,
			WriteTimeout:                  cfg.WriteTimeout,
			DisableHeaderNamesNormalizing: true,
		},
		cfg: cfg,
	}
	rc.req = fasthttp.AcquireRequest()
	rc.resp = fasthttp.AcquireResponse()
	return rc
}

// RESTsend performs a http request (using cfg for the options) and returns
// the http status code + nil on success or 600 and an error.
// It's thread safe (can be called in parallel for the same client).
func (rc *RESTclient) RESTsend(url string, body string) (int, error) {
	cfg := &rc.cfg
	req := rc.req
	if req == nil {
		req = fasthttp.AcquireRequest()
	}
	req.SetRequestURI(url)
	req.Header.SetMethod(cfg.Method)
	req.Header.SetContentType(cfg.ContentType)
	if len(cfg.XHeaders) > 0 {
		req.Header.DisableNormalizing()
		for _, h := range cfg.XHeaders {
			cpos := strings.IndexByte(h, ':')
			if cpos > 0 {
				req.Header.Add(h[:cpos], h[(cpos+1):])
			}
		}
	}
	req.SetBodyString(body)

	resp := rc.resp
	if resp == nil {
		resp = fasthttp.AcquireResponse()
	}
	client := rc.c

	rstatus := 600
	httpErr := client.DoRedirects(req, resp, cfg.MaxRedirects)
	if httpErr == nil {
		rstatus = resp.StatusCode()
	}

	if rc.req == nil {
		fasthttp.ReleaseRequest(req)
	} else {
		req.Reset()
	}
	if rc.resp == nil {
		fasthttp.ReleaseResponse(resp)
	} else {
		resp.Reset()
	}
	return rstatus, httpErr
}
