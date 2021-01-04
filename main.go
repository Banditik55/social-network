package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"text/template"
	"time"

	"github.com/google/uuid"
	env "github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

const (
	pagesPath = "pages/"
)

var (
	mongoClient *mongo.Client
)

func main() {
	// _uuid, _ := uuid.NewRandom()
	// fmt.Println(_uuid.String())
	// _uuid, _ := uuid.Parse("f441e9e8-9a97-43fb-84be-faaee4089de30")

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
		profile := false
		if len(path) >= 2 {
			if path[0:2] == "/@" {
				profile = true
			}
		}
		switch path {
		default:
			if profile {
				link := path[2:]
				fmt.Println(link)

				tmpl, err := template.ParseFiles(pagesPath + "profile.html")
				if err != nil {
					http.Error(w, err.Error(), 404)
					return
				}

				if err := tmpl.Execute(w, nil); err != nil {
					http.Error(w, err.Error(), 404)
					return
				}
			} else {
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
		case "/register":
			// cookieLogin, _ := r.Cookie("login")
			// cookieToken, _ := r.Cookie("token")
			// if cookieLogin != nil && cookieToken != nil {
			// 	http.Redirect(w, r, "/profile", http.StatusSeeOther)
			// 	return
			// }

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
		case "/login":
			// cookieLogin, _ := r.Cookie("login")
			// cookieToken, _ := r.Cookie("token")
			// if cookieLogin != nil && cookieToken != nil {
			// 	http.Redirect(w, r, "/profile", http.StatusSeeOther)
			// 	return
			// }

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
		case "/profile":
			cookieLogin, _ := r.Cookie("login")
			cookieToken, _ := r.Cookie("token")
			if cookieLogin == nil || cookieToken == nil {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}

			user, err := findUser(cookieLogin.Value)
			if err != nil {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}

			check := comparePasswords(cookieToken.Value, []byte(user.ID.String()+user.Password))
			if check {
				tmpl, err := template.ParseFiles(pagesPath + "myProfile.html")
				if err != nil {
					http.Error(w, err.Error(), 404)
					return
				}

				_time := time.Unix(user.Date, 0)

				// posts := []map[string]string{
				// 	{
				// 		"title": "hello",
				// 		"image": "from server",
				// 	},
				// }

				posts := findPostsFromUserID(user.ID.Hex())

				type Parse struct {
					User
					NewDate time.Time
					NewID   string
					Posts   []bson.M
				}
				parse := Parse{
					User:    user,
					NewDate: _time,
					NewID:   user.ID.Hex(),
					Posts:   posts,
				}
				if err := tmpl.Execute(w, parse); err != nil {
					http.Error(w, err.Error(), 404)
					return
				}
			} else {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
		case "/api/telegramAuthNotify":
			cookieLogin, _ := r.Cookie("login")
			cookieToken, _ := r.Cookie("token")
			if cookieLogin == nil || cookieToken == nil {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}

			user, err := findUser(cookieLogin.Value)
			if err != nil {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}

			check := comparePasswords(cookieToken.Value, []byte(user.ID.String()+user.Password))
			if check {
				collection := mongoClient.Database("main").Collection("users")
				id, _ := primitive.ObjectIDFromHex(user.ID.Hex())

				filter := bson.M{"_id": bson.M{"$eq": id}}
				update := bson.D{{"$set", bson.D{
					{"telegram_auth_notify", false},
				}}}
				opts := options.Update().SetUpsert(true)
				result, err := collection.UpdateOne(context.Background(), filter, update, opts)
				if err != nil {
					fmt.Println(err)
				}
				fmt.Println("updated:", result.ModifiedCount)
			} else {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
		case "/api/test":
			type Article struct {
				Title   string `json:"Title"`
				Desc    string `json:"desc"`
				Content string `json:"content"`
			}

			Articles := []Article{
				Article{Title: "Hello", Desc: "Article Description", Content: "Article Content"},
				Article{Title: "Hello 2", Desc: "Article Description", Content: "Article Content"},
			}
			json.NewEncoder(w).Encode(Articles)
		case "/logout":
			cookie := &http.Cookie{
				Name:   "login",
				Value:  "",
				MaxAge: -1,
			}
			_cookie := &http.Cookie{
				Name:   "token",
				Value:  "",
				MaxAge: -1,
			}
			http.SetCookie(w, cookie)
			http.SetCookie(w, _cookie)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
		case "/posts/remove":
			cookieLogin, _ := r.Cookie("login")
			cookieToken, _ := r.Cookie("token")
			if cookieLogin == nil || cookieToken == nil {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}

			keys, ok := r.URL.Query()["q"]

			if !ok || len(keys[0]) < 1 {
				http.Error(w, "", 200)
			} else {
				id := keys[0]
				_id, _ := primitive.ObjectIDFromHex(id)
				post, err := findPostFromID(_id)
				if err != nil {
					http.Error(w, "", 200)
					return
				}

				user, err := findUser(cookieLogin.Value)
				if err != nil {
					http.Redirect(w, r, "/login", http.StatusSeeOther)
					return
				}

				check := comparePasswords(cookieToken.Value, []byte(user.ID.String()+user.Password))
				if check {
					collection := mongoClient.Database("main").Collection("posts")
					id, _ := primitive.ObjectIDFromHex(user.ID.Hex())

					filter := bson.M{"_id": bson.M{"$eq": post.ID}, "uid": bson.M{"$eq": id.Hex()}}
					update := bson.D{{"$set", bson.D{
						{"hide", true},
					}}}
					opts := options.Update().SetUpsert(true)
					_, err := collection.UpdateOne(context.Background(), filter, update, opts)
					if err != nil {
						http.Redirect(w, r, "/login", http.StatusSeeOther)
						return
					}

					http.Error(w, "", 200)
					return
				} else {
					http.Redirect(w, r, "/login", http.StatusSeeOther)
					return
				}
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
			hashedPassword, err := hashAndSalt([]byte(password))
			if err != nil {
				fmt.Fprintln(w, err)
				return
			}
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

			_, _err := findUser(login)
			if _err != nil {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				collection := mongoClient.Database("main").Collection("users")

				link, _ := uuid.NewRandom()
				_link := link.String()
				_link = strings.ReplaceAll(_link, "-", "")
				id := primitive.NewObjectID()

				user := User{
					ID:                 id,
					Login:              login,
					Password:           hashedPassword,
					Name:               name,
					Description:        "",
					Country:            "",
					Avatar:             "",
					Link:               _link,
					Date:               time.Now().Unix(),
					TelegramAccount:    0,
					AuthWithTelegram:   false,
					TelegramAuthNotify: true,
					Role:               "user",
				}
				_, err := collection.InsertOne(ctx, user)
				if err != nil {
					fmt.Fprintln(w, err)
					return
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

			user, err := findUser(login)
			if err != nil {
				createCookie(w, "login_info", "Incorrect username or password.")
				http.Redirect(w, r, "/login", http.StatusSeeOther)
			} else {
				check := comparePasswords(user.Password, []byte(password))
				if check {
					token, err := hashAndSalt([]byte(user.ID.String() + user.Password))
					if err != nil {
						fmt.Fprintln(w, err)
						return
					}

					maxAge := 3600

					cookie := &http.Cookie{
						Name:     "login",
						Value:    user.Login,
						MaxAge:   maxAge,
						Secure:   true,
						HttpOnly: true,
					}
					_cookie := &http.Cookie{
						Name:     "token",
						Value:    token,
						MaxAge:   maxAge,
						Secure:   true,
						HttpOnly: true,
					}
					http.SetCookie(w, cookie)
					http.SetCookie(w, _cookie)
					http.Redirect(w, r, "/profile", http.StatusSeeOther)
				} else {
					createCookie(w, "login_info", "Incorrect username or password.")
					http.Redirect(w, r, "/login", http.StatusSeeOther)
				}
			}
		case "/posts/create":
			if err := r.ParseForm(); err != nil {
				fmt.Fprintf(w, "ParseForm() err: %v", err)
				return
			}
			text := r.FormValue("text")
			image := r.FormValue("image")

			if len(text) < 1 {
				http.Redirect(w, r, "/profile", http.StatusSeeOther)
				return
			}

			cookieLogin, _ := r.Cookie("login")
			cookieToken, _ := r.Cookie("token")
			if cookieLogin == nil || cookieToken == nil {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}

			user, err := findUser(cookieLogin.Value)
			if err != nil {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}

			check := comparePasswords(cookieToken.Value, []byte(user.ID.String()+user.Password))
			if check {
				collection := mongoClient.Database("main").Collection("posts")
				id := primitive.NewObjectID()

				like := PostLike{
					Up:   []string{},
					Down: []string{},
				}
				post := Post{
					ID:    id,
					UID:   user.ID.Hex(),
					Date:  time.Now().Unix(),
					Text:  text,
					Image: image,
					Hide:  false,
					Like:  like,
				}
				_, err := collection.InsertOne(context.Background(), post)
				if err != nil {
					fmt.Fprintln(w, err)
					return
				}

				http.Redirect(w, r, "/profile", http.StatusSeeOther)
				return
			} else {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
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

func hashAndSalt(password []byte) (string, error) {
	hash, err := bcrypt.GenerateFromPassword(password, bcrypt.MinCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func comparePasswords(hashedPassword string, password []byte) bool {
	byteHash := []byte(hashedPassword)
	err := bcrypt.CompareHashAndPassword(byteHash, password)
	if err != nil {
		return false
	}
	return true
}

func findPostsFromUserID(uid string) []bson.M {
	collection := mongoClient.Database("main").Collection("posts")

	opts := options.Find()
	cursor, err := collection.Find(context.TODO(), bson.D{{"uid", uid}}, opts)
	if err != nil {
		log.Fatal(err)
	}

	var results []bson.M
	if err = cursor.All(context.TODO(), &results); err != nil {
		return []bson.M{}
	}
	// for _, result := range results {
	// 	return result
	// }
	return results
}

func findPostFromID(id primitive.ObjectID) (Post, error) {
	collection := mongoClient.Database("main").Collection("posts")
	var post Post
	err := collection.FindOne(context.TODO(), bson.M{
		"_id": id,
	}).Decode(&post)
	if err != nil {
		return post, err
	}
	return post, nil
}

type User struct {
	ID                 primitive.ObjectID `bson:"_id"`
	Login              string             `bson:"login"`
	Password           string             `bson:"password"`
	Name               string             `bson:"name"`
	Description        string             `bson:"description"`
	Country            string             `bson:"country"`
	Avatar             string             `bson:"avatar"`
	Link               string             `bson:"link"`
	Date               int64              `bson:"date"`
	TelegramAccount    int                `bson:"telegram_account"`
	AuthWithTelegram   bool               `bson:"auth_with_telegram"`
	TelegramAuthNotify bool               `bson:"telegram_auth_notify"`
	Role               string             `bson:"role"`
}

type Post struct {
	ID    primitive.ObjectID `bson:"_id"`
	UID   string             `bson:"uid"`
	Date  int64              `bson:"date"`
	Text  string             `bson:"text"`
	Image string             `bson:"image"`
	Hide  bool               `bson:"hide"`
	Like  PostLike
}

type PostLike struct {
	Up   []string `bson:"up"`
	Down []string `bson:"down"`
}
