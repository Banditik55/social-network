package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"text/template"
	"time"

	env "github.com/joho/godotenv"
	uuid "github.com/satori/go.uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	pagesPath = "pages/"
)

var (
	mongoClient *mongo.Client
)

func main() {
	_uuid, _ := uuid.FromString("8b5d9b9b-dffe-4116-bba0-1fbc4769b676")
	u1 := uuid.NewV5(_uuid, "dmitry")
	fmt.Println(_uuid, u1)

	// Parsing UUID from string input
	// u2, err := uuid.FromString(u1.String())
	// if err != nil {
	// 	fmt.Println("Something gone wrong:", err)
	// }
	// fmt.Println("Successfully parsed:", u2)

	go mongoInit()
	webInit()
}

func mongoInit() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var err error
	mongoClient, err = mongo.Connect(ctx, options.Client().ApplyURI(
		"mongodb+srv://admin:ALCy22ziJQ8cPfEt@cluster.wbqd8.mongodb.net/main?retryWrites=true&w=majority",
	))
	if err != nil {
		panic(err)
	}

	// collection := mongoClient.Database("main").Collection("users")

	// var result struct {
	// 	Value float64
	// }

	// type Post struct {
	// 	Login string  `json:”login,omitempty”`
	// 	Pi    float64 `json:”pi,omitempty”`
	// }
	// var post Post
	// err = collection.FindOne(ctx, bson.M{
	// 	"login": "banditik55",
	// }).Decode(&post)
	// if err != nil {
	// 	fmt.Println("FindOne error", err)
	// }
	// fmt.Println(post)

	// res, err := collection.InsertOne(ctx, bson.M{
	// 	"login": "banditik55",
	// 	"pi":    3.1415,
	// })
	// id := res.InsertedID
	// fmt.Println("InsertOne", id, res)
}

func webInit() {
	envErr := env.Load(".env")
	if envErr != nil {
		panic("error loading .env file")
	}

	http.HandleFunc("/", webRender)
	port := os.Getenv("PORT")
	fmt.Println("http server started on port", port)
	panic(http.ListenAndServe(":"+port, nil))
}

func webRender(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		path := r.URL.Path
		switch path {
		default:
			if isFile(path) {
				if checkFileExists("." + path) {
					http.ServeFile(w, r, "."+path)
				} else {
					http.Error(w, "Error 404", 404)
				}
			} else {
				tmpl, err := template.ParseFiles(pagesPath + "404.html")
				if err != nil {
					http.Error(w, err.Error(), 404)
					return
				}

				if err := tmpl.Execute(w, nil); err != nil {
					http.Error(w, err.Error(), 404)
					return
				}
			}
		case "/":
			tmpl, err := template.ParseFiles(pagesPath + "login.html")
			if err != nil {
				http.Error(w, err.Error(), 404)
				return
			}

			if err := tmpl.Execute(w, nil); err != nil {
				http.Error(w, err.Error(), 404)
				return
			}
		case "/register", "/register/":
			cookie, _ := r.Cookie("register_info")
			var info string
			if cookie != nil {
				info = cookie.Value
				removeCookie(w, "register_info")
			}
			type Data struct {
				Info string
			}
			data := Data{
				Info: info,
			}
			tmpl, err := template.ParseFiles(pagesPath + "register.html")
			if err != nil {
				http.Error(w, err.Error(), 404)
				return
			}

			if err := tmpl.Execute(w, data); err != nil {
				http.Error(w, err.Error(), 404)
				return
			}
		case "/login", "/login/":
			cookie, _ := r.Cookie("login_info")
			var info string
			if cookie != nil {
				info = cookie.Value
				removeCookie(w, "login_info")
			}
			type Data struct {
				Info string
			}
			data := Data{
				Info: info,
			}

			tmpl, err := template.ParseFiles(pagesPath + "login.html")
			if err != nil {
				http.Error(w, err.Error(), 404)
				return
			}

			if err := tmpl.Execute(w, data); err != nil {
				http.Error(w, err.Error(), 404)
				return
			}
		case "/test":
			// ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			// defer cancel()
			// collection := mongoClient.Database("main").Collection("users")
			// type Post struct {
			// 	Login string  `json:”login,omitempty”`
			// 	Pi    float64 `json:”pi,omitempty”`
			// }
			// var post Post
			// find := collection.FindOne(ctx, bson.M{
			// 	"login": "banditik55",
			// }).Decode(&post)
			// if find != nil {
			// 	w.Write([]byte("user not found"))
			// }
			// fmt.Fprintln(w, "user found", post.Pi)
			// log.Println("/test")

			// w.Write([]byte("/test - hello from server"))
		}
	case "POST":
		path := r.URL.Path
		switch path {
		case "/register":
			if err := r.ParseForm(); err != nil {
				fmt.Fprintf(w, "ParseForm() err: %v", err)
				return
			}
			login := r.FormValue("login")
			login = strings.ToLower(strings.ReplaceAll(login, " ", ""))
			password := r.FormValue("password")
			name := r.FormValue("name")

			if len(login) < 4 {
				createCookie(w, "register_info", "min. login characters: 4")
				http.Redirect(w, r, "/register", http.StatusSeeOther)
				return
			} else if len(password) < 4 {
				createCookie(w, "register_info", "min. password characters: 4")
				http.Redirect(w, r, "/register", http.StatusSeeOther)
				return
			} else if len(name) < 1 {
				createCookie(w, "register_info", "min. name characters: 1")
				http.Redirect(w, r, "/register", http.StatusSeeOther)
				return
			}

			_, err := findUser(login)
			if err != nil {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				collection := mongoClient.Database("main").Collection("users")
				_, err := collection.InsertOne(ctx, bson.M{
					"login":    login,
					"password": password,
					"name":     name,
				})
				if err != nil {
					fmt.Println(err)
				}
				http.Redirect(w, r, "/login", http.StatusSeeOther)
			} else {
				createCookie(w, "register_info", "login already exists")
				http.Redirect(w, r, "/register", http.StatusSeeOther)
			}
		case "/login":
			if err := r.ParseForm(); err != nil {
				fmt.Fprintf(w, "ParseForm() err: %v", err)
				return
			}
			login := r.FormValue("login")
			password := r.FormValue("password")

			if len(login) < 4 {
				createCookie(w, "login_info", "min. login characters: 4")
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			} else if len(password) < 4 {
				createCookie(w, "login_info", "min. password characters: 4")
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}

			_, err := findUser(login)
			if err != nil {
				createCookie(w, "login_info", "Incorrect username or password.")
				http.Redirect(w, r, "/login", http.StatusSeeOther)
			} else {
				createCookie(w, "login_info", "user found")
				http.Redirect(w, r, "/login", http.StatusSeeOther)
			}
		}
	default:
		fmt.Fprintf(w, "go home samurai")
	}
}

func checkFileExists(path string) bool {
	if _, err := os.Stat(path); err == nil {
		return true
	}
	return false
}

func isFile(v string) bool {
	return strings.Contains(v, ".")
}

func isPublicPath(path string) bool {
	if len(path) >= 8 && strings.Contains(path, "/public/") && path[0:8] == "/public/" {
		return true
	}
	return false
}

func findUser(login string) (User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	collection := mongoClient.Database("main").Collection("users")
	var user User
	err := collection.FindOne(ctx, bson.M{
		"login": login,
	}).Decode(&user)
	if err != nil {
		return user, err
	}
	return user, nil
}

func removeCookie(w http.ResponseWriter, name string) {
	cookie := &http.Cookie{
		Name:   name,
		Value:  "",
		MaxAge: -1,
	}
	http.SetCookie(w, cookie)
}

func createCookie(w http.ResponseWriter, name, value string) {
	cookie := &http.Cookie{
		Name:   name,
		Value:  value,
		MaxAge: 60,
	}
	http.SetCookie(w, cookie)
}

type User struct {
	Login string  `json:”login,omitempty”`
	Pi    float64 `json:”pi,omitempty”`
}
