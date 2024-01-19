package server

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/golangast/endrulats/assets"
	"github.com/golangast/endrulats/src/funcmaps"
	"github.com/golangast/endrulats/src/routes"

	"github.com/Masterminds/sprig/v3"

	"github.com/golangast/endrulats/internal/dbsql/user"
	"github.com/golangast/endrulats/internal/rand"
	"github.com/golangast/endrulats/src/handler/get/welcome"

	"github.com/golangast/endrulats/internal/security/tokens"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/labstack/gommon/log"
	"github.com/spf13/viper"
)

func Server() {

	e := echo.New()
	files, err := getAllFilenames(&assets.Assets)
	if err != nil {
		fmt.Print(err)
	}

	//if you are planning on using binary assets then use this but if you turn it on then
	//you have to rebuild every time you rerun it.
	// filesoptimized, err := getAllFilenames(&assets.AssetsOptimized)
	// if err != nil {
	// 	fmt.Print(err)
	// }

	//for CSP policy to ensure that the assets are always available and secure
	jsr := findjsrename()
	cssr := findcssrename()
	rr := rand.Rander()

	Nonce := fmt.Sprintf("nounce='" + rr + "'")
	viper.SetConfigName("assetdirectory") // name of config file (without extension)
	viper.SetConfigType("yaml")           // REQUIRED if the config file does not have the extension in the name
	viper.AddConfigPath("./optimize/")    // path to look for the config file in
	err = viper.ReadInConfig()            // Find and read the config file
	if err != nil {
		fmt.Println(err)
	}
	//get paths of asset folders from config file
	cssout := viper.GetString("opt.cssout")
	jsout := viper.GetString("opt.jsout")

	cssnew := strings.ReplaceAll(cssout, "min", "min"+cssr)
	jsnew := strings.ReplaceAll(jsout, "min", "min"+jsr)

	UpdateText("./optimize/assetdirectory.yaml", cssout, cssnew)
	UpdateText("./optimize/assetdirectory.yaml", jsout, jsnew)
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
	r.GET("/welcome/:email/:sitetoken", welcome.Welcome)

	e.Use(middleware.StaticWithConfig(middleware.StaticConfig{
		Filesystem: getFileSystem(assets.Assets),
		HTML5:      true,
	}))
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"*"},
		AllowMethods: []string{http.MethodGet, http.MethodHead, http.MethodPut, http.MethodPatch, http.MethodPost, http.MethodDelete},
	}))

	routes.Routes(e)

	// Route
	e.Logger.SetLevel(log.ERROR)
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	// Generate a nonce

	e.Use(middleware.SecureWithConfig(middleware.SecureConfig{
		XSSProtection: "1; mode=block",
		// XFrameOptions:         "SAMEORIGIN",
		HSTSMaxAge:            31536000,
		ContentSecurityPolicy: "default-src 'self'; style-src 'self'; frame-src youtube.com www.youtube.com; 'nonce-" + Nonce + "'",
	}))

	e.Use(middleware.CSRFWithConfig(middleware.CSRFConfig{
		TokenLookup:    "header:headkey",
		CookiePath:     "/",
		CookieDomain:   "161.35.101.49",
		CookieSecure:   true,
		CookieHTTPOnly: true,
	}))
	e.Use(middleware.BodyLimit("3M"))
	e.IPExtractor = echo.ExtractIPDirect()
	e.Use(middleware.GzipWithConfig(middleware.GzipConfig{
		Level: 5,
	}))
	e.Static("/", "assets/optimized")
	e.Use(middleware.RateLimiter(middleware.NewRateLimiterMemoryStore(30)))

	// for new cert go here https://stackoverflow.com/questions/45508442/golang-https-with-ecdsa-certificate-from-openssl

	e.Logger.Fatal(e.Start(":5002"))

}

func GetAllFilePathsInDirectory(dirpath string) ([]string, error) {
	var paths []string
	err := filepath.Walk(dirpath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return paths, nil
}

func ParseDirectory(dirpath string) (*template.Template, error) {
	paths, err := GetAllFilePathsInDirectory(dirpath)
	if err != nil {
		return nil, err
	}
	return template.ParseFiles(paths...)
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

func getFileSystem(TmplMainGo embed.FS) http.FileSystem {

	log.Print("using embed mode")
	fsys, err := fs.Sub(TmplMainGo, "assets/templates")
	if err != nil {
		log.Print(err)
	}

	return http.FS(fsys)
}

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

	rr := rand.Rander()
	New_Path := "./assets/optimized/js/min" + rr + ".js"
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

	return rr
}

func findcssrename() string {
	// Get the current directory
	currentDir := "./assets/optimized/css/"

	rr := rand.Rander()
	New_Path := "./assets/optimized/css/min" + rr + ".css"
	// Walk the directory and print the names of all the files
	err = filepath.Walk(currentDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			fmt.Println(err)
			return err
		}

		if strings.Contains(path, "/min") && strings.Contains(path, ".css") {

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

	return rr
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
