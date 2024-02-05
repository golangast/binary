package main

import (
	"bytes"
	"context"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/acme/autocert"

	"github.com/golangast/endrulats/assets"
	"github.com/golangast/endrulats/src/funcmaps"
	"github.com/golangast/endrulats/src/handler/get/profile"
	"github.com/golangast/endrulats/src/routes"

	// "github.com/golangast/goservershell/assets"

	"crypto/tls"

	"github.com/Masterminds/sprig/v3"
	"github.com/golangast/endrulats/internal/dbsql/createtable"
	"github.com/golangast/endrulats/internal/dbsql/user"
	"github.com/golangast/endrulats/internal/rand"

	"github.com/golangast/endrulats/internal/security/tokens"
	"github.com/golangast/gentil/utility/ff"
	"github.com/golangast/gentil/utility/temp"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/labstack/gommon/log"
	"github.com/spf13/viper"
	"golang.org/x/crypto/acme"
)

//go:embed all:assets/optimized
var AssetsOptimize embed.FS

func main() {

	e := echo.New()

	files, err := getAllFilenames(&assets.Assets)
	if err != nil {
		fmt.Print(err)
	}
	if _, err := os.Stat("assets/config/assetdirectory.yaml"); errors.Is(err, os.ErrNotExist) {

		file, err := ff.Makefile("assets/config/assetdirectory.yaml")
		if err != nil {
			fmt.Print(err)
		}

		var config = `opt:
 sassin: ./assets/build/sass
 sasspartials: ./assets/build/partials
 sassout: ./assets/build/css
 cssin: ./assets/build/css
 cssout: ./assets/optimized/css/min740cdd0edad3d26f1.css
 jsin: ./assets/build/js
 jsout: ./assets/optimized/js/min1d460f4.js
 imgin: ./assets/optimized/img`

		err = temp.Writetemplate(config, file, nil)
		if err != nil {
			fmt.Print(err)
		}

	}
	if _, err := os.Stat("assets/db/database.db"); errors.Is(err, os.ErrNotExist) {
		_, err := ff.Makefile("assets/db/database.db")
		if err != nil {
			fmt.Print(err)
		}

		err = createtable.CreateTable()
		if err != nil {
			fmt.Println(err)
		}

	}
	//for CSP policy to ensure that the assets are always available and secure
	id := uuid.New().String()

	jsr := findjsrename()
	cssr := findcssrename()

	rr := rand.Rander()

	Nonce := fmt.Sprintf(`nonce="` + rr + id[0:10] + `"`)
	PNonce := fmt.Sprintf(`'nonce-` + rr + id[0:10] + `'`)

	viper.SetConfigName("assetdirectory") // name of config file (without extension)
	viper.SetConfigType("yaml")           // REQUIRED if the config file does not have the extension in the name
	viper.AddConfigPath(".")              // path to look for the config file in
	err = viper.ReadInConfig()            // Find and read the config file
	if err != nil {
		fmt.Println(err)
	}
	//get paths of asset folders from config file
	cssout := viper.GetString("opt.cssout")
	jsout := viper.GetString("opt.jsout")

	cssnew := strings.ReplaceAll(cssout, "min", "min"+cssr)
	jsnew := strings.ReplaceAll(jsout, "min", "min"+jsr)

	UpdateText("./assetdirectory.yaml", cssout, cssnew)
	UpdateText("./assetdirectory.yaml", jsout, jsnew)
	Noncer := template.HTMLAttr(Nonce)
	e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {

			c.Set("n", Noncer)
			c.Set("jsr", jsr)
			c.Set("cssr", cssr)
			return next(c)
		}
	})

	renderer := &TemplateRenderer{
		templates: template.Must(template.New("t").Funcs(template.FuncMap{
			"IndexCount":     funcmaps.IndexCount,
			"RemoveBrackets": funcmaps.RemoveBrackets,
		}).Funcs(sprig.FuncMap()).ParseFS(assets.Assets, files...)),
	}

	e.Renderer = renderer

	queryAuthConfig := middleware.KeyAuthConfig{
		KeyLookup: "query:sitetoken,header:headkey,cookie:goservershell",
		Validator: func(key string, c echo.Context) (bool, error) {
			user := new(user.Users)
			email := c.Param("email")
			idkey := c.Param("sitetoken")

			err, exists := user.CheckUser(c, email, idkey)
			if err != nil {
				fmt.Println("middleware", exists)
				return false, err
			}

			fmt.Println(key, " keylookup")
			b := tokens.Checktokencontext(key)
			return b, nil
		},

		ErrorHandler: func(error, echo.Context) error {
			var err error

			return err
		},
	}
	r := e.Group("/restricted")
	r.Use(middleware.KeyAuthWithConfig(queryAuthConfig))
	r.GET("/usercreate/:email/:sitetoken", profile.Profile)

	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"*"},
		AllowHeaders: []string{"Authorization", "Content-Type"},
		AllowMethods: []string{http.MethodGet, http.MethodHead, http.MethodPut, http.MethodPatch, http.MethodPost, http.MethodDelete},
	}))

	routes.Routes(e)

	// Route
	e.Logger.SetLevel(log.ERROR)
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	e.Use(middleware.RequestLoggerWithConfig(middleware.RequestLoggerConfig{
		LogStatus:   true,
		LogURI:      true,
		LogError:    true,
		HandleError: true, // forwards error to the global error handler, so it can decide appropriate status code
		LogValuesFunc: func(c echo.Context, v middleware.RequestLoggerValues) error {
			if v.Error == nil {
				logger.LogAttrs(context.Background(), slog.LevelInfo, "REQUEST",
					slog.String("uri", v.URI),
					slog.Int("status", v.Status),
				)
			} else {
				logger.LogAttrs(context.Background(), slog.LevelError, "REQUEST_ERROR",
					slog.String("uri", v.URI),
					slog.Int("status", v.Status),
					slog.String("err", v.Error.Error()),
				)
			}
			return nil
		},
	}))
	// Generate a nonce

	var works = "frame-src youtube.com www.youtube.com; default-src 'self'; style-src " + PNonce + " 'self' https://endrulats.com *.endrulats.com *.endrulats.com/*; img-src  " + PNonce + " 'self' https://endrulats.com *.endrulats.com *.endrulats.com/*; style-src-elem " + PNonce + " *.localhost:5002/*;"
	var script = "connect-src " + PNonce + " *.localhost:5002/* *.google-analytics.com *.googletagmanager.com;base-uri 'self'; object-src 'none'; script-src " + PNonce + " *.googletagmanager.com; report-uri https://endrulats.com *.endrulats.com *.endrulats.com/*;script-src-elem " + PNonce + " *.googletagmanager.com;"
	e.Use(middleware.SecureWithConfig(middleware.SecureConfig{
		XSSProtection:         "1; mode=block",
		XFrameOptions:         "SAMEORIGIN",
		HSTSMaxAge:            31536000,
		ContentSecurityPolicy: works + script,
		HSTSPreloadEnabled:    true,
		ContentTypeNosniff:    "nosniff",
	}))

	e.Use(middleware.BodyLimit("3M"))
	e.IPExtractor = echo.ExtractIPDirect()
	e.Use(middleware.GzipWithConfig(middleware.GzipConfig{
		Level: 5,
	}))

	e.Use(middleware.RateLimiter(middleware.NewRateLimiterMemoryStore(30)))

	e.AutoTLSManager.Cache = autocert.DirCache("/var/www/.cache")
	e.Use(middleware.Recover())
	e.Use(middleware.Logger())
	e.Use(middleware.StaticWithConfig(middleware.StaticConfig{
		HTML5:      true,
		Root:       "assets/optimized/",
		Filesystem: http.FS(AssetsOptimize),
	}))
	autoTLSManager := autocert.Manager{
		Prompt: autocert.AcceptTOS,
		// Cache certificates to avoid issues with rate limits (https://letsencrypt.org/docs/rate-limits)
		Cache:      autocert.DirCache("/var/www/.cache"),
		HostPolicy: autocert.HostWhitelist("endrulats.com"),
	}

	s := http.Server{
		Addr:    ":443",
		Handler: e, // set Echo as handler
		TLSConfig: &tls.Config{
			Certificates:   nil, // <-- s.ListenAndServeTLS will populate this field
			GetCertificate: autoTLSManager.GetCertificate,
			NextProtos:     []string{acme.ALPNProto},
		},
		ReadTimeout: 30 * time.Second, // use custom timeouts
	}
	keyspem, err := assets.Keypem.ReadFile("certs/key.pem")
	if err != nil {
		fmt.Println(err)
	}
	certspem, err := assets.Certpem.ReadFile("certs/cert.pem")
	if err != nil {
		fmt.Println(err)
	}
	if err := s.ListenAndServeTLS(string(certspem), string(keyspem)); err != http.ErrServerClosed {
		e.Logger.Fatal(err)
	}

	//e.Logger.Fatal(e.Start(":5002"))
	// for new cert go here https://stackoverflow.com/questions/45508442/golang-https-with-ecdsa-certificate-from-openssl

}

type TemplateRenderer struct {
	templates *template.Template
}

// Render renders a template document
func (t *TemplateRenderer) Render(w io.Writer, name string, data interface{}, c echo.Context) error {

	// Add global methods if data is a map
	if viewContext, isMap := data.(map[string]interface{}); isMap {
		viewContext["reverse"] = c.Echo().Reverse
	}

	return t.templates.ExecuteTemplate(w, name, data)
}

var err error

// https://gist.github.com/clarkmcc/1fdab4472283bb68464d066d6b4169bc
func getAllFilenames(efs *embed.FS) (files []string, err error) {
	if err := fs.WalkDir(efs, ".", func(path string, d fs.DirEntry, err error) error {
		if d.IsDir() {
			return nil
		}

		files = append(files, path)

		return nil
	}); err != nil {
		return nil, err
	}

	return files, nil
}

func findjsrename() string {
	// Get the current directory
	currentDir := "./assets/optimized/js/"

	id := "3333"

	if len(id) > 15 {
		id = id[0:8]
	}

	New_Path := "./assets/optimized/js/min" + id + ".js"
	// Walk the directory and print the names of all the files
	err = filepath.Walk(currentDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			fmt.Println(err)
			return err
		}

		if strings.Contains(path, "/min") && strings.Contains(path, ".js") {

			if _, err := os.Stat(New_Path); err != nil {
				// The source does not exist or some other error accessing the source
				fmt.Println("source:", err)
			}

			if _, err := os.Stat(path); err != nil {
				// The destination exists or some other error accessing the destination
				fmt.Println("dest:", err)
			}
			if err := os.Rename(path, New_Path); err != nil {
				fmt.Println(err)
			}

		} else {
			fmt.Println("doesnt contain directory", path)
		}

		return nil
	})

	if err != nil {
		fmt.Println(err)
	}

	return id
}

func findcssrename() string {
	// Get the current directory
	currentDir := "./assets/optimized/css/"

	// id := uuid.New().String()
	id := "3333"
	if len(id) > 15 {
		id = id[0:8]
	}

	New_Path := "./assets/optimized/css/min" + id + ".css"
	// Walk the directory and print the names of all the files
	err = filepath.Walk(currentDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			fmt.Println(err)
			return err
		}

		if strings.Contains(path, "css/min") && strings.Contains(path, ".css") {

			if _, err := os.Stat(New_Path); err != nil {
				// The source does not exist or some other error accessing the source
				fmt.Println("source:", err)
			}

			if _, err := os.Stat(path); err != nil {
				// The destination exists or some other error accessing the destination
				fmt.Println("dest:", err)
			}
			if err := os.Rename(path, New_Path); err != nil {
				fmt.Println(err)
			}

		} else {
			fmt.Println("doesnt contain directory", path)
		}

		return nil
	})

	if err != nil {
		fmt.Println(err)
	}

	return id
}

// f is for file, o is for old text, n is for new text
func UpdateText(f string, o string, n string) {
	fmt.Println(f, o, n)
	input, err := os.ReadFile(f)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	output := bytes.Replace(input, []byte(o), []byte(n), -1)

	fmt.Println("file: ", f, " old: ", o, " new: ", n)

	if err = os.WriteFile(f, output, 0666); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
