package utiles

import (
	"bytes"
	"encoding/json"
	"fmt"
)

//Indent  缩进序列化
func Indent(b []byte) string {
	var out bytes.Buffer
	err := json.Indent(&out, b, "", "    ")
	if err != nil {
		return fmt.Sprintf("%+v", string(b))
	}
	return out.String()
}
