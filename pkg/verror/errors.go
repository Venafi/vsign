package verror

import "fmt"

var (
	VsignError                      = fmt.Errorf("vsign error")
	ServerError                     = fmt.Errorf("%w: server error", VsignError)
	ServerUnavailableError          = fmt.Errorf("%w: server unavailable", ServerError)
	ServerTemporaryUnavailableError = fmt.Errorf("%w: temporary", ServerUnavailableError)
	ServerBadDataResponce           = fmt.Errorf("%w: server returns 400 code. your request has problems", ServerError)
	UserDataError                   = fmt.Errorf("%w: your data contains problems", VsignError)
	AuthError                       = fmt.Errorf("%w: auth error", UserDataError)
)
