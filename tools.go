package tools

import (
	"bytes"
	"fmt"
	"json"
)

func Indent(b []byte) string {
	var out bytes.Buffer
	err := json.Indent(&out, b, "", "    ")
	if err != nil {
		return fmt.Sprintf("%+v", string(b))
	}
	return out.String()
}
