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
	envErr := env.Load(".env")
	if envErr != nil {
		panic("error loading .env file")
	}

	mongoInit()
	webInit()

	// fmt.Println(bson.D{{"k", "v"}, {"k2", "v2"}})
	// fmt.Println(bson.A{"k", "v", "k2", "v2"})
	// fmt.Println(bson.M{"k": "v", "k2": "v2"})
}

func mongoInit() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var err error
	mongoClient, err = mongo.Connect(ctx, options.Client().ApplyURI(os.Getenv("MONGO_DB")))
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

	// type Trainer struct {
	// 	Name    string
	// 	Country string
	// }

	// collection := mongoClient.Database("main").Collection("users")

	// options := options.Find()
	// filter := bson.M{}

	//------
	// var results []*Trainer
	// cur, err := collection.Find(context.TODO(), filter, options)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// for cur.Next(context.TODO()) {

	// 	var elem Trainer
	// 	err := cur.Decode(&elem)
	// 	fmt.Println(elem)
	// 	if err != nil {
	// 		log.Fatal(err)
	// 	}

	// 	results = append(results, &elem)
	// }

	// if err := cur.Err(); err != nil {
	// 	log.Fatal(err)
	// }

	// cur.Close(context.TODO())

	// fmt.Println(results[0])
	// fmt.Printf("Found multiple documents (array of pointers): %+v\n", results)
}

func webInit() {
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

				user, err := getUserFromLink(link)
				if err != nil {
					tmpl, err := template.ParseFiles(pagesPath + "404.html")
					if err != nil {
						http.Error(w, err.Error(), 404)
						return
					}

					if err := tmpl.Execute(w, nil); err != nil {
						http.Error(w, err.Error(), 404)
						return
					}
				} else {
					tmpl, err := template.ParseFiles(pagesPath+"profile.html", pagesPath+"_assets.html")
					if err != nil {
						http.Error(w, err.Error(), 404)
						return
					}

					loggedIn := false
					cookieLogin, _ := r.Cookie("login")
					cookieToken, _ := r.Cookie("token")
					if cookieLogin != nil && cookieToken != nil {
						loggedIn = true
					}

					_time := time.Unix(user.Date, 0)
					posts := getPostsFromUserID(user.ID.Hex())
					type Parse struct {
						User
						NewDate  time.Time
						NewID    string
						Posts    []Post
						LoggedIn bool
					}
					parse := Parse{
						User:     user,
						NewDate:  _time,
						NewID:    user.ID.Hex(),
						Posts:    posts,
						LoggedIn: loggedIn,
					}

					if err := tmpl.Execute(w, parse); err != nil {
						http.Error(w, err.Error(), 404)
						return
					}
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
			http.Redirect(w, r, "/profile", http.StatusSeeOther)
			return
		case "/register":
			cookieLogin, _ := r.Cookie("login")
			cookieToken, _ := r.Cookie("token")
			if cookieLogin != nil && cookieToken != nil {
				_, err := getUserFromLogin(cookieLogin.Value)
				if err == nil {
					http.Redirect(w, r, "/profile", http.StatusSeeOther)
					return
				}
			}

			cookie, _ := r.Cookie("register_info")
			var info string
			if cookie != nil {
				info = cookie.Value
				removeNotifyCookie(w, "register_info")
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
			cookieLogin, _ := r.Cookie("login")
			cookieToken, _ := r.Cookie("token")
			if cookieLogin != nil && cookieToken != nil {
				_, err := getUserFromLogin(cookieLogin.Value)
				if err == nil {
					http.Redirect(w, r, "/profile", http.StatusSeeOther)
					return
				}
			}

			cookie, _ := r.Cookie("login_info")
			var info string
			if cookie != nil {
				info = cookie.Value
				removeNotifyCookie(w, "login_info")
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
			activeCookie := isActiveCookie(r)
			if !activeCookie {
				http.Redirect(w, r, "/logout", http.StatusSeeOther)
				return
			}

			cookieLogin, _ := r.Cookie("login")
			cookieToken, _ := r.Cookie("token")

			user, err := getUserFromLogin(cookieLogin.Value)
			if err != nil {
				http.Redirect(w, r, "/logout", http.StatusSeeOther)
				return
			}

			check := comparePasswords(cookieToken.Value, []byte(user.ID.String()+user.Password))
			if check {
				tmpl, err := template.ParseFiles(pagesPath+"myProfile.html", pagesPath+"_assets.html")
				if err != nil {
					http.Error(w, err.Error(), 404)
					return
				}

				_time := time.Unix(user.Date, 0).Format("01-02-2006")
				posts := getPostsFromUserID(user.ID.Hex())

				for i, v := range posts {
					posts[i].FullDate = time.Unix(v.Date, 0).Format("01-02-2006")
				}

				type Parse struct {
					User
					NewDate  string
					NewID    string
					Posts    []Post
					LoggedIn bool
				}
				parse := Parse{
					User:     user,
					NewDate:  _time,
					NewID:    user.ID.Hex(),
					Posts:    posts,
					LoggedIn: true,
				}
				if err := tmpl.Execute(w, parse); err != nil {
					http.Error(w, err.Error(), 404)
					return
				}
			} else {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
		case "/myProfile/telegramAuthNotify":
			cookieLogin, _ := r.Cookie("login")
			cookieToken, _ := r.Cookie("token")
			if cookieLogin == nil || cookieToken == nil {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}

			user, err := getUserFromLogin(cookieLogin.Value)
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
				_, err := collection.UpdateOne(context.Background(), filter, update, opts)
				if err != nil {
					fmt.Println(err)
				}
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
		case "/myProfile/removePost":
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
				post, err := getPostFromID(_id)
				if err != nil {
					http.Error(w, "", 200)
					return
				}

				user, err := getUserFromLogin(cookieLogin.Value)
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
		case "/settings":
			cookieLogin, _ := r.Cookie("login")
			cookieToken, _ := r.Cookie("token")
			if cookieLogin != nil && cookieToken != nil {
				_, err := getUserFromLogin(cookieLogin.Value)
				if err != nil {
					http.Redirect(w, r, "/login", http.StatusSeeOther)
					return
				}
			}

			user, err := getUserFromLogin(cookieLogin.Value)
			if err != nil {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}

			check := comparePasswords(cookieToken.Value, []byte(user.ID.String()+user.Password))
			if check {
				tmpl, err := template.ParseFiles(pagesPath+"settings.html", pagesPath+"_assets.html")
				if err != nil {
					http.Error(w, err.Error(), 404)
					return
				}

				_time := time.Unix(user.Date, 0)
				posts := getPostsFromUserID(user.ID.Hex())

				type Parse struct {
					User
					NewDate  time.Time
					NewID    string
					Posts    []Post
					LoggedIn bool
				}
				parse := Parse{
					User:     user,
					NewDate:  _time,
					NewID:    user.ID.Hex(),
					Posts:    posts,
					LoggedIn: true,
				}
				if err := tmpl.Execute(w, parse); err != nil {
					http.Error(w, err.Error(), 404)
					return
				}
			} else {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
		case "/about":
			tmpl, err := template.ParseFiles(pagesPath + "about.html")
			if err != nil {
				http.Error(w, err.Error(), 404)
				return
			}

			if err := tmpl.Execute(w, nil); err != nil {
				http.Error(w, err.Error(), 404)
				return
			}
		case "/users":
			tmpl, err := template.ParseFiles(pagesPath+"users.html", pagesPath+"_assets.html")
			if err != nil {
				http.Error(w, err.Error(), 404)
				return
			}

			loggedIn := false
			cookieLogin, _ := r.Cookie("login")
			cookieToken, _ := r.Cookie("token")
			if cookieLogin != nil && cookieToken != nil {
				loggedIn = true
			}

			users := getAllUsers()
			for i, v := range users {
				users[i].FullDate = time.Unix(v.Date, 0).Format("2006-01-02 15:04:05")
			}

			type Parse struct {
				LoggedIn bool
				Users    []User
			}
			parse := Parse{
				LoggedIn: loggedIn,
				Users:    users,
			}

			if err := tmpl.Execute(w, parse); err != nil {
				http.Error(w, err.Error(), 404)
				return
			}
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
				createNotifyCookie(w, "register_info", "min. login characters: 4")
				http.Redirect(w, r, "/register", http.StatusSeeOther)
				return
			} else if len(password) < 4 {
				createNotifyCookie(w, "register_info", "min. password characters: 4")
				http.Redirect(w, r, "/register", http.StatusSeeOther)
				return
			} else if len(name) < 1 {
				createNotifyCookie(w, "register_info", "min. name characters: 1")
				http.Redirect(w, r, "/register", http.StatusSeeOther)
				return
			}

			_, _err := getUserFromLogin(login)
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
				createNotifyCookie(w, "register_info", "login already exists")
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
				createNotifyCookie(w, "login_info", "min. login characters: 4")
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			} else if len(password) < 4 {
				createNotifyCookie(w, "login_info", "min. password characters: 4")
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}

			user, err := getUserFromLogin(login)
			if err != nil {
				createNotifyCookie(w, "login_info", "Incorrect username or password.")
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
					createNotifyCookie(w, "login_info", "Incorrect username or password.")
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

			user, err := getUserFromLogin(cookieLogin.Value)
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
		case "/settings/changePassword":
			if err := r.ParseForm(); err != nil {
				fmt.Fprintf(w, "ParseForm() err: %v", err)
				return
			}
			new := r.FormValue("new")

			cookieLogin, _ := r.Cookie("login")
			cookieToken, _ := r.Cookie("token")
			if cookieLogin == nil || cookieToken == nil {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}

			user, err := getUserFromLogin(cookieLogin.Value)
			if err != nil {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}

			check := comparePasswords(cookieToken.Value, []byte(user.ID.String()+user.Password))
			if check {
				hashedPassword, err := hashAndSalt([]byte(new))
				if err != nil {
					fmt.Fprintln(w, err)
					return
				}

				collection := mongoClient.Database("main").Collection("users")
				filter := bson.M{"_id": bson.M{"$eq": user.ID}}
				opts := options.Update().SetUpsert(true)
				update := bson.D{{"$set", bson.D{
					{"password", hashedPassword},
				}}}
				res, err := collection.UpdateOne(context.TODO(), filter, update, opts)
				if err != nil {
					http.Error(w, "", http.StatusForbidden)
					return
				}
				if res.ModifiedCount > 0 {
					http.Redirect(w, r, "/logout", http.StatusSeeOther)
					return
				} else {
					http.Error(w, "", http.StatusNotFound)
					return
				}
			} else {
				http.Error(w, "", http.StatusForbidden)
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

func getUserFromLogin(login string) (User, error) {
	collection := mongoClient.Database("main").Collection("users")
	var user User
	err := collection.FindOne(context.TODO(), bson.M{
		"login": login,
	}).Decode(&user)
	if err != nil {
		return user, err
	}
	return user, nil
}

func removeNotifyCookie(w http.ResponseWriter, name string) {
	cookie := &http.Cookie{
		Name:   name,
		Value:  "",
		MaxAge: -1,
	}
	http.SetCookie(w, cookie)
}

func createNotifyCookie(w http.ResponseWriter, name, value string) {
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

func getPostsFromUserID(uid string) []Post {
	collection := mongoClient.Database("main").Collection("posts")

	opts := options.Find()
	cursor, err := collection.Find(context.TODO(), bson.D{{"uid", uid}}, opts)
	if err != nil {
		log.Fatal(err)
	}

	var results []Post
	if err = cursor.All(context.TODO(), &results); err != nil {
		return []Post{}
	}
	// for _, result := range results {
	// 	return result
	// }
	return results
}

func getPostFromID(id primitive.ObjectID) (Post, error) {
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

func getUserFromLink(link string) (User, error) {
	collection := mongoClient.Database("main").Collection("users")
	var user User
	err := collection.FindOne(context.TODO(), bson.M{
		"link": link,
	}).Decode(&user)
	if err != nil {
		return user, err
	}
	return user, nil
}

func getAllUsers() []User {
	collection := mongoClient.Database("main").Collection("users")
	opts := options.Find()
	cursor, err := collection.Find(context.TODO(), bson.D{{}}, opts)
	if err != nil {
		log.Fatal(err)
	}

	var results []User
	if err = cursor.All(context.TODO(), &results); err != nil {
		return []User{}
	}

	return results
}

func isActiveCookie(r *http.Request) bool {
	cookieLogin, err := r.Cookie("login")
	cookieToken, err := r.Cookie("token")
	if err != nil {
		return false
	}
	if cookieLogin != nil && cookieToken != nil {
		return true
	}
	return false
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
	FullDate           string             `bson:"full_date,omitempty"`
}

type Post struct {
	ID       primitive.ObjectID `bson:"_id"`
	UID      string             `bson:"uid"`
	Date     int64              `bson:"date"`
	Text     string             `bson:"text"`
	Image    string             `bson:"image"`
	Hide     bool               `bson:"hide"`
	FullDate string             `bson:"full_date"`
	Like     PostLike
}

type PostLike struct {
	Up   []string `bson:"up"`
	Down []string `bson:"down"`
}
