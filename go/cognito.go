package main

import (
    "fmt"
    "github.com/aws/aws-sdk-go/aws"
    "github.com/aws/aws-sdk-go/aws/credentials"
    "github.com/aws/aws-sdk-go/aws/session"
    "github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"log"
	// "encoding/json"
	// "regexp"
	// "strings"
)

type ChallengeResponse struct {
    ChallengeName        string            `json:"ChallengeName"`
    ChallengeParameters  map[string]string `json:"ChallengeParameters"`
    Session              string            `json:"Session"`
}

func main() {
    // 使用您的AWS凭据和区域配置
    awsRegion := "ap-southeast-1"
    awsAccessKeyId := ""
    awsSecretAccessKey := ""
    // userPoolId := "ap-southeast-1_osrkuGXu4"
    clientId := "dllb69draepao1p6sqplv71r"

    // 创建一个新的会话
    sess, err := session.NewSession(&aws.Config{
        Region:      aws.String(awsRegion),
        // Credentials: credentials.NewStaticCredentials(awsAccessKeyId, awsSecretAccessKey, ""),
		// LogLevel:    aws.LogLevel(aws.LogDebugWithHTTPBody), 
    })
    if err != nil {
        fmt.Println("NewSession error:", err)
        return
    }

    // 创建一个Cognito Identity Provider客户端
    svc := cognitoidentityprovider.New(sess)

    // 用户登录凭据
    username := "billysun"
    password := "Test1234."

    // 初始化登录请求
    params := &cognitoidentityprovider.InitiateAuthInput{
        AuthFlow: aws.String("USER_PASSWORD_AUTH"),
        AuthParameters: map[string]*string{
            "USERNAME": aws.String(username),
            "PASSWORD": aws.String(password),
        },
        ClientId: aws.String(clientId),
    }

    // 发起登录请求
    resp, err := svc.InitiateAuth(params)
    if err != nil {
        fmt.Println("Error initiating auth: ", err)
        return
    }

	// fmt.Printf("Challenge Name: %s\n", *resp.Session)

	if (*resp.ChallengeName == "SOFTWARE_TOKEN_MFA") {
		var inputVal = ""
		fmt.Print("Enter MFA Code: ")
		fmt.Scanln(&inputVal)
		// fmt.Println("You entered:", inputVal)

		input := &cognitoidentityprovider.RespondToAuthChallengeInput{
			ChallengeName: aws.String("SOFTWARE_TOKEN_MFA"),
			ClientId:      aws.String(clientId),
			Session:       aws.String(*resp.Session),
			ChallengeResponses: map[string]*string{
				"USERNAME": aws.String(username),
				"SOFTWARE_TOKEN_MFA_CODE": aws.String(inputVal),
			},
		}
		
		result, err := svc.RespondToAuthChallenge(input)
		if err != nil {
			// 处理错误
		}

		fmt.Println(*result.AuthenticationResult.IdToken)
	}

	// fmt.Printf("Auth successful: %+v\n", resp)

	// re := regexp.MustCompile(`(\w+):`)
    // standardJSON := re.ReplaceAllStringFunc(resp.String(), func(match string) string {
    //     return `"` + strings.TrimSuffix(match, ":") + `":`
    // })

    // fmt.Println(standardJSON)

	// jsonData := []byte(standardJSON)

	// var challengeResponse ChallengeResponse

    // err = json.Unmarshal(jsonData, &challengeResponse)

    if err != nil {
        log.Fatalf("Error unmarshalling ChallengeResponse: %v", err)
    }
	
}
