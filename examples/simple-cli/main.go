package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/venafi/vsign/pkg/endpoint"
	"github.com/venafi/vsign/pkg/vsign"
)

func main() {
	vSignCfg, err := vsign.BuildConfigWithAuth(context.Background(), os.Getenv("TPP_URL"), &endpoint.Authentication{}, "")

	if err != nil {
		panic(fmt.Errorf("error building config"))
	}
	vSignCfg.Credentials.AccessToken = os.Getenv("ACCESS_TOKEN")
	vSignCfg.Project = os.Getenv("TPP_PROJECT")
	connector, err := vsign.NewClient(&vSignCfg)

	if err != nil {
		panic(fmt.Errorf("unable to connect to %s: %s", vSignCfg.ConnectorType, err))
	}

	e, err := connector.GetEnvironment()
	if err != nil {
		panic(fmt.Errorf("getenvironment error: %s", err.Error()))
	}

	sig, err := connector.Sign(&endpoint.SignOption{
		KeyID:     e.KeyID,
		Mechanism: 64,
		DigestAlg: "sha256",
		Payload:   []byte(base64.StdEncoding.EncodeToString([]byte("this is a test payload"))),
		B64Flag:   true,
		RawFlag:   false,
	})

	if err != nil {
		panic(err)
	}

	fmt.Println(base64.StdEncoding.EncodeToString(sig))
}
