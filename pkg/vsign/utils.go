package vsign

import (
	"fmt"

	"github.com/spf13/viper"
)

const (
	vSignURL         = "VSIGN_URL"
	vSignProject     = "VSIGN_PROJECT"
	vSignKeyLabel    = "VSIGN_KEY_LABEL"
	vSignToken       = "VSIGN_TOKEN"
	vSignAPIKey      = "VSIGN_APIKEY"
	vSignJWT         = "VSIGN_JWT"
	vSignTrustBundle = "VSIGN_TRUST_BUNDLE"
	vSignLogLevel    = "VSIGN_LOG_LEVEL"
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
