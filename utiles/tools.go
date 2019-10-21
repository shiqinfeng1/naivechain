package utiles

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"time"
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

func RandValue() string {
	var r = make([]byte, 32)
	rand.Seed(time.Now().UnixNano())
	n, _ := rand.Read(r)
	if n == 32 {
		return hex.EncodeToString(r)
	}
	return ""
}
