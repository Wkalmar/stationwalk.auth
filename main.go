package main

import (
	"net/http"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
)

func clientError(status int) (events.APIGatewayProxyResponse, error) {
	return events.APIGatewayProxyResponse{
		StatusCode: status,
		Body:       http.StatusText(status),
	}, nil
}

func HandleRequest(req events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	jwtToken, err := Auth(req.Body)

	if err != nil {
		return clientError(http.StatusForbidden)
	}

	return events.APIGatewayProxyResponse{
		StatusCode: http.StatusOK,
		Body:       jwtToken,
	}, nil
}

func main() {
	lambda.Start(HandleRequest)
}
