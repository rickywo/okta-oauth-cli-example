package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

var wg sync.WaitGroup
var code string
var stateResponse string

func AuthServer() string {
	domain := os.Getenv("OKTA_DOMAIN")
	response, _ := http.Get(domain + "/.well-known/oauth-authorization-server")
	body, _ := ioutil.ReadAll(response.Body)
	defer response.Body.Close()
	var result map[string]interface{}
	json.Unmarshal(body, &result)
	return result["authorization_endpoint"].(string)
}

func Authorize(c *gin.Context) {
	params := c.Request.URL.Query()
	code = params["code"][0]
	stateResponse = params["state"][0]
	response := "You may now close the browser."
	wg.Done()
	c.String(http.StatusOK, response)
}

func HttpServer() {
	r := gin.Default()
	r.GET("/callback", Authorize)
	r.Run(":8080")
}

func main() {
	wg.Add(1)
	go HttpServer()

	state := make([]byte, 5)
	rand.Read(state)
	server := AuthServer()
	request, _ := http.NewRequest("GET", server, nil)
	query := request.URL.Query()
	query.Add("response_type", "code")
	query.Add("client_id", os.Getenv("OKTA_CLIENT_ID"))
	query.Add("redirect_uri", "http://localhost:8080/callback")
	query.Add("state", string(state))
	query.Add("scope", "openid")
	request.URL.RawQuery = query.Encode()
	fmt.Println("Enter this URL into a browser:", request.URL.String())

	wg.Wait()
	time.Sleep(2 * time.Second)

	fmt.Println(string(state), stateResponse)
	fmt.Println(code)

	// Compare state
	// Exchange code for token
	// Mke API call
}
