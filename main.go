package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

func requireStringEnv(key string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		log.Fatalf("$%v required", key)
	}
	return value
}

func requireIntEnv(key string) int {
	strValue := requireStringEnv(key)
	value, err := strconv.Atoi(strValue)
	if err != nil {
		log.Fatalf("$%v must be an integer", key)
	}
	return value
}

func exportEnv(key, value string) {
	cmdLog, err := exec.Command("bitrise", "envman", "add", "--key", key, "--value", value).CombinedOutput()
	if err != nil {
		log.Fatalf("error exporting environment variable with envman: %#v | output: %s", err, cmdLog)
	}
}

type AccessTokenResponse struct {
	Token      string
	Expires_at string
}

// https://docs.github.com/en/developers/apps/building-github-apps/authenticating-with-github-apps#authenticating-as-a-github-app
func main() {
	apiBaseUrl := requireStringEnv("api_base_url")
	appId := requireIntEnv("app_id")
	installationId := requireIntEnv("installation_id")

	privateKeyPem := requireStringEnv("private_key_pem")
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(privateKeyPem))
	if err != nil {
		log.Fatal("$private_key_pem must be in valid PEM format: ", err)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		// issued at time, 60 seconds in the past to allow for clock drift
		"iat": time.Now().Add(-time.Minute).Unix(),
		// JWT expiration time (10 minute maximum)
		"exp": time.Now().Add(10 * time.Minute).Unix(),
		// GitHub App's identifier
		"iss": appId,
	})

	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		log.Fatal("error signing: ", err)
	}

	if !strings.HasSuffix(apiBaseUrl, "/") {
		apiBaseUrl += "/"
	}
	url := fmt.Sprintf("%vapp/installations/%v/access_tokens", apiBaseUrl, installationId)

	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		log.Fatal("error creating request: ", err)
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %v", tokenString))
	req.Header.Add("Accept", "application/vnd.github.v3+json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal("error sending request: ", err)
	}

	if resp.StatusCode != http.StatusCreated {
		body, _ := ioutil.ReadAll(resp.Body)
		log.Fatalf("unexpected status code %v: %v", resp.StatusCode, string(body))
	}

	var accessToken AccessTokenResponse
	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(&accessToken)
	if err != nil {
		log.Fatal("error decoding JSON: ", err)
	}

	if accessToken.Token == "" || accessToken.Expires_at == "" {
		log.Fatal("could not get token or its expiration date")
	}

	exportEnv("GITHUB_API_TOKEN", accessToken.Token)
	exportEnv("GITHUB_API_TOKEN_EXPIRES_AT", accessToken.Expires_at)
}
