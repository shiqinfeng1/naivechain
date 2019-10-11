package utiles

import (
	"fmt"

	"github.com/shiqinfeng1/gorequest"
)

//KeyPair KeyPair
type KeyPair struct {
	PrivKey string `json:"privKey"`
	PubKey  string `json:"pubKey"`
}

var url = "http://localhost:8088/"

//RequestKeyPair 申请新的秘钥对
func RequestKeyPair() (KeyPair, error) {
	var result KeyPair
	httpClient := gorequest.New()
	_, _, errs := httpClient.Get(url + "new_keypair").EndStruct(&result)
	if errs != nil {
		err := fmt.Errorf("requestKeyPair %s error: %q", url, errs)
		return KeyPair{}, err
	}
	return result, nil
}
