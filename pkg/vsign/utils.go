package vsign

import (
	"fmt"

	"github.com/spf13/viper"
)

const (
	vSignURL         = "VSIGN_URL"
	vSignProject     = "VSIGN_PROJECT"
	vSignToken       = "VSIGN_TOKEN"
	vSignJWT         = "VSIGN_JWT"
	vSignTrustBundle = "VSIGN_TRUST_BUNDLE"
)

func getPropertyFromEnvironment(s string) string {
	viper.AutomaticEnv()

	urlS := viper.Get(s)

	if urlS == nil {

		return ""

	} else {

		return fmt.Sprintf("%v", urlS)

	}

}
