package cors_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/orange-cloudfoundry/gobis-middlewares/cors"
	"github.com/orange-cloudfoundry/gobis/gobistest"
)

var _ = Describe("Cors", func() {
	var midTest *gobistest.MiddlewareTest
	BeforeEach(func() {
		midTest = gobistest.NewSimpleMiddlewareTest(
			gobistest.CreateInlineParams("cors",
				"enabled", true,
			),
			cors.NewCors(),
		)
	})
	Context("simple cors enable", func() {
		It("should add cors when user enable it", func() {
			req := midTest.CreateRequest()
			req.Header.Add("Origin", "http://localhost")
			resp := midTest.Run(req)

			Expect(resp.Header).To(HaveKey("Access-Control-Allow-Origin"))
			Expect(resp.Header.Get("Access-Control-Allow-Origin")).To(Equal("*"))
		})
		It("should add cors when origin is correct", func() {
			midTest.AddMiddlewareParamToFirst("allowed_origins", []string{"http://fake.domain.com"})

			req := midTest.CreateRequest()
			req.Header.Add("Origin", "http://fake.domain.com")
			resp := midTest.Run(req)

			Expect(resp.Header).To(HaveKey("Access-Control-Allow-Origin"))
			Expect(resp.Header.Get("Access-Control-Allow-Origin")).To(Equal("http://fake.domain.com"))
		})
		It("should not add cors when user didn't enabled it", func() {
			midTest.AddMiddlewareParamToFirst("enabled", false)

			req := midTest.CreateRequest()
			req.Header.Add("Origin", "http://localhost")
			resp := midTest.Run(req)

			Expect(resp.Header).ToNot(HaveKey("Access-Control-Allow-Origin"))
		})
		It("should not add cors when method is not allowed", func() {
			midTest.SetMiddlewareParams(struct {
				cors.CorsConfig
			}{cors.CorsConfig{
				&cors.CorsOptions{
					Enabled:        true,
					AllowedMethods: []string{"POST"},
				},
			}})

			req := midTest.CreateRequest()
			req.Header.Add("Origin", "http://localhost")
			resp := midTest.Run(req)

			Expect(resp.Header).ToNot(HaveKey("Access-Control-Allow-Origin"))
		})
		It("should not add cors when origin is wrong", func() {
			midTest.AddMiddlewareParamToFirst("allowed_origins", []string{"http://fake.domain.com"})

			req := midTest.CreateRequest()
			req.Header.Add("Origin", "http://localhost")
			resp := midTest.Run(req)

			Expect(resp.Header).ToNot(HaveKey("Access-Control-Allow-Origin"))
		})
	})
})
