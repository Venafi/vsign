package shared

var LateHooks []func()

func AddLateHook(f func()) {
	LateHooks = append(LateHooks, f)
}
