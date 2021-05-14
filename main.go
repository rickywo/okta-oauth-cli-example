package main

import (
	b64 "encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

var wg sync.WaitGroup
var code string
var stateResponse string

func AuthServer() map[string]interface{} {
	domain := os.Getenv("OKTA_ISSUER_URI")
	response, _ := http.Get(domain + "/.well-known/oauth-authorization-server")
	body, _ := ioutil.ReadAll(response.Body)
	defer response.Body.Close()
	var result map[string]interface{}
	json.Unmarshal(body, &result)
	return result
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

func GenerateURL(auth_server string, state string) {
	request, _ := http.NewRequest("GET", auth_server, nil)
	query := request.URL.Query()
	query.Add("response_type", "code")
	query.Add("client_id", os.Getenv("OKTA_CLIENT_ID"))
	query.Add("redirect_uri", "http://localhost:8080/callback")
	query.Add("state", state)
	query.Add("scope", "openid")
	request.URL.RawQuery = query.Encode()
	fmt.Println("Enter this URL into a browser:\n", request.URL.String())
}

func API(server string, auth string, values url.Values) map[string]interface{} {
	client := &http.Client{}
	request, _ := http.NewRequest("POST", server, strings.NewReader(values.Encode()))
	request.Header.Set("Authorization", auth)
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	response, _ := client.Do(request)
	var result map[string]interface{}
	json.NewDecoder(response.Body).Decode(&result)
	return result
}

func ExchangeCodeForToken(server string, auth string, code string) string {
	values := url.Values{}
	values.Set("grant_type", "authorization_code")
	values.Set("code", code)
	values.Set("redirect_uri", "http://localhost:8080/callback")

	result := API(server, auth, values)
	return result["access_token"].(string)
}

func Introspect(server string, auth string, token string) {
	values := url.Values{}
	values.Set("token", token)
	values.Set("token_hint_type", "access_token")

	result := API(server, auth, values)
	fmt.Println("Active:", result["active"], "Username:", result["username"])
}

func main() {
	wg.Add(1)
	go HttpServer()

	client_id := os.Getenv("OKTA_CLIENT_ID")
	client_secret := os.Getenv("OKTA_CLIENT_SECRET")
	auth := "Basic " + b64.URLEncoding.EncodeToString([]byte(client_id+":"+client_secret))

	state_bytes := make([]byte, 5)
	rand.Read(state_bytes)
	state := hex.EncodeToString(state_bytes)

	servers := AuthServer()
	GenerateURL(servers["authorization_endpoint"].(string), state)

	wg.Wait()

	if state != stateResponse {
		fmt.Println("Invalid state returned")
		time.Sleep(2 * time.Second)
		os.Exit(1)
	}

	access_token := ExchangeCodeForToken(servers["token_endpoint"].(string), auth, code)
	Introspect(servers["introspection_endpoint"].(string), auth, access_token)
}
