package utils

import (
	"bytes"
	"net/http"
)

type ResponseData struct {
	Header http.Header
	Code   int
	Body   []byte
}

func NewResponseModifier(rw http.ResponseWriter) *ResponseModifier {
	return &ResponseModifier{
		headers: cloneHttpHeader(rw.Header()),
		body:    new(bytes.Buffer),
		code:    200,
	}
}

type ResponseModifier struct {
	code    int
	headers http.Header
	body    *bytes.Buffer
	rw      http.ResponseWriter
}

func (rm ResponseModifier) Header() http.Header {
	return rm.headers
}

func (rm ResponseModifier) Write(body []byte) (int, error) {
	return rm.body.Write(body)
}

func (rm ResponseModifier) WriteHeader(statusCode int) {
	rm.code = statusCode
}

func (rm ResponseModifier) Modify(mod func(data ResponseData) (ResponseData, error)) error {
	returnData, err := mod(ResponseData{
		Header: rm.headers,
		Body:   rm.body.Bytes(),
		Code:   rm.code,
	})
	if err != nil {
		return err
	}
	i := 0
	added := make([]string, len(returnData.Header))
	for k, vl := range returnData.Header {
		if len(vl) == 0 {
			continue
		}
		if len(vl) > 1 {
			for _, v := range vl {
				rm.rw.Header().Add(k, v)
			}
		} else {
			rm.rw.Header().Set(k, vl[0])
		}

		added[i] = k
		i++
	}
	for k := range rm.rw.Header() {
		index := -1
		for i, v := range added {
			if v == k {
				index = i
				break
			}
		}
		if index < 0 {
			rm.rw.Header().Del(k)
		}
	}
	_, err = rm.rw.Write(returnData.Body)
	if err != nil {
		return err
	}
	rm.rw.WriteHeader(returnData.Code)
	return nil
}

func cloneHttpHeader(headers http.Header) http.Header {
	newHeaders := make(http.Header)
	for k, vl := range headers {
		newValues := make([]string, len(vl))
		copy(newValues, vl)
		newHeaders[k] = newValues
	}
	return newHeaders
}
