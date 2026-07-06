package devmode

import (
	"os"
	"strings"
)

func Enabled() bool {
	v := strings.TrimSpace(os.Getenv("NEXQLOUD_DEV"))
	return v == "1" || strings.EqualFold(v, "true")
}
