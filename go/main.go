package main

import (
	"fmt"
    "crypto/rsa"
    "encoding/base64"
    "math/big"
	"log"
	"encoding/json"
	"github.com/dgrijalva/jwt-go"
    "net/http"
    "io/ioutil"
	"time"
)

type JWKSet struct {
    Keys []JWK `json:"keys"`
}

// 假设 JWK 结构
type JWK struct {
    Kty string `json:"kty"`
    N   string `json:"n"`
    E   string `json:"e"`
    // 其他可能的字段...
}

// 从 JWK 转换为 rsa.PublicKey
func jwkToRSAPublicKey(jwk *JWK) (*rsa.PublicKey, error) {
    // 解码模数
    nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
    if err != nil {
        return nil, err
    }
    n := new(big.Int).SetBytes(nBytes)

    // 解码指数
    eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
    if err != nil {
        return nil, err
    }
    var e int = 0
    for _, b := range eBytes {
        e = e*256 + int(b)
    }

    return &rsa.PublicKey{N: n, E: e}, nil
}

func main() {
    // 假设你已经有了从 Cognito JWKs 端点获取的 JSON 字符串

	userPoolId := "ap-southeast-1_JIi7tYFv0"
    region := "ap-southeast-1"

	jwksUrl := fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json", region, userPoolId)
    resp, err := http.Get(jwksUrl)

    if err != nil {
        log.Fatal("Error parsing jwksUrl: ", err)
    }

    defer resp.Body.Close()

    body, err := ioutil.ReadAll(resp.Body)

    if err != nil {
        log.Fatal("Error parsing reponse body: ", err)
    }

	strBody := string(body)

	// fmt.Println("----> : ", strBody)

    jwksJson := strBody

    var jwkSet JWKSet
    err = json.Unmarshal([]byte(jwksJson), &jwkSet)
    if err != nil {
        log.Fatalf("Error unmarshalling JWKs: %v", err)
    }

    // 假设我们只关心第一个密钥
    if len(jwkSet.Keys) > 0 {
        publicKey, err := jwkToRSAPublicKey(&jwkSet.Keys[0])
        if err != nil {
            log.Fatalf("Error converting JWK to RSA PublicKey: %v", err)
        }

        // 现在 publicKey 是 *rsa.PublicKey 类型，可用于验证 JWT

		// fmt.Println("-> ",publicKey.N.String());

		// 假设 JWT 令牌
		tokenString := "eyJraWQiOiJrM2dCQjlNUXE5RGI4cGt2Z0xIMFVURXVDM2RpVFh1WVNRaEVRdmdXamFvPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiJkN2YyMTMzYi1mNGQxLTRlZTUtYTEzNy1hNDhlZTAyODNhZTciLCJpc3MiOiJodHRwczpcL1wvY29nbml0by1pZHAuYXAtc291dGhlYXN0LTEuYW1hem9uYXdzLmNvbVwvYXAtc291dGhlYXN0LTFfSklpN3RZRnYwIiwiY29nbml0bzp1c2VybmFtZSI6ImJpbGx5c3VuIiwib3JpZ2luX2p0aSI6IjQwNDJhNjBkLTIyNTAtNDM4NS1iYTk2LWY2ZWZkMGM5ZjQwMSIsImF1ZCI6IjRkdXFtZzVvMzAwa3JlNnRybGdlNzF0N2NrIiwiZXZlbnRfaWQiOiJiZjQ1MDBiOS0xZDFkLTQ2NzctOTU0YS1mZmExZjg5MmJhOTUiLCJ0b2tlbl91c2UiOiJpZCIsImF1dGhfdGltZSI6MTcwOTEwOTY5NCwibmFtZSI6IkNoYW9xdW4iLCJleHAiOjE3MDkxMTMyOTQsImlhdCI6MTcwOTEwOTY5NCwianRpIjoiNDBkNzY4OGYtZGJhMy00ODhmLTg2N2YtMThiMjNiYjE0YjhjIiwiZW1haWwiOiJzdW5jaGFvcXVuQDEyNi5jb20ifQ.dGL5cK8keWihhn-bqNJQy5_DzCXq7jCZ0nP5K8T2ut8eXK-GBw-xeOIF7L7kMLdEkeSIH_Ed5xpb-_8hMnY1zFhZ4CDgHBDXzkE2fziYCv7nYLw7ksjCGcu2Lppy_14y8lwMTvDzSrcg9FxSY8RLpCVVsfKYVjwnbvYUOiHxauDTxdlHiFns_BrQ2l_B2Hr3-G3cUhPCAwgabxfCjtyC366u14aECzBofETInrkz2xd7T8DGvsLWrE8Fj4IjH3DLWWSkA1uznzgPH7tyfMHKU-ZzRsg5vyVzv9cug_JqRxMlj_SpWpT_I7wvJyLHQIEEkD5XpcCTczhqFQDuW9agFg"

		// 解析并验证 JWT
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// 确保令牌使用了正确的签名算法
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}

			// 返回公钥
			return publicKey, nil
		})

		if err != nil {
			log.Fatal("Error parsing token: ", err)
		}

		// 检查令牌是否有效
		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			fmt.Println("User ID: ", claims["sub"]) // 或者其他你关心的字段
			fmt.Println("User Name: ", claims["name"]) // 或者其他你关心的字段
			fmt.Println("User Email: ", claims["email"]) // 或者其他你关心的字段
			

			exp, ok := claims["exp"].(float64)

			// fmt.Println("The time is", claims["exp"])

			if !ok {
				// 处理错误
			}

			// time.Now()
			currentTime :=  time.UnixMilli(int64(exp * float64(1000.0))) 
			
			fmt.Printf("User will be expired: %d-%d-%d %d:%d:%d\n",
				currentTime.Year(),
				currentTime.Month(),
				currentTime.Day(),
				currentTime.Hour(),
				currentTime.Minute(),
				currentTime.Second())
		} else {
			fmt.Println("Invalid token")
		}
    }
}
