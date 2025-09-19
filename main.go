package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/iveteran/OAuth2WebFlow/controller"
	"github.com/iveteran/OAuth2WebFlow/service"

	_ "github.com/mattn/go-sqlite3"
)

// 自定义ResponseWriter用于捕获状态码
type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.statusCode = code
	lrw.ResponseWriter.WriteHeader(code)
}

// 日志中间件
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// 创建一个自定义的ResponseWriter来捕获状态码
		lrw := &loggingResponseWriter{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
		}

		// 执行下一个处理器
		next.ServeHTTP(lrw, r)

		// 记录日志
		log.Printf("%s %s %d %v %s",
			r.Method,
			r.RequestURI,
			lrw.statusCode,
			time.Since(start),
			r.RemoteAddr,
		)
	})
}

func main() {
	db, err := sql.Open("sqlite3", "./oauth2.db")
	if err != nil {
		log.Fatal(err)
	}

	authService := &service.AuthService{DB: db}
	authController := &controller.AuthController{Service: authService}

	authService.InitDB()

	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", authController.Authorize)
	mux.HandleFunc("/callback", authController.Callback)
	mux.HandleFunc("/get_token", authController.GetToken)

	// 使用日志中间件包装处理器
	loggedMux := loggingMiddleware(mux)

	fmt.Println("Server running at http://localhost:9090")
	log.Fatal(http.ListenAndServe(":9090", loggedMux))
}
