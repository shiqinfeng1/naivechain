package utiles

import (
	"encoding/json"

	"github.com/shiqinfeng1/gorequest"
)

//KeyPair KeyPair
type KeyPair struct {
	PrivKey string `json:"privKey"`
	PubKey  string `json:"pubKey"`
}

//ReqChameleonHash 请求变色龙hash的参数
type ReqChameleonHash struct {
	PubKeys []string `json:"pubkeys"`
	R       string   `json:"r"`
	RawMsg  string   `json:"rawmsg"`
}

//RespChameleonHash 变色龙hash响应
type RespChameleonHash struct {
	CHash string `json:"chash"`
	R     string `json:"r"`
}

var url = "http://localhost:8088/"

//RequestKeyPair 申请新的秘钥对
func RequestKeyPair() (KeyPair, error) {
	var result KeyPair
	_, _, errs := gorequest.New().Get(url + "new_keypair").EndStruct(&result)
	if errs != nil {
		//err := fmt.Errorf("requestKeyPair %s error: %q", url, errs)
		//return KeyPair{}, err
		return KeyPair{PrivKey: RandValue(), PubKey: RandValue()}, nil
	}
	return result, nil
}

//RequestChameleonHash 申请新的秘钥对
func RequestChameleonHash(rch ReqChameleonHash) (RespChameleonHash, error) {
	var result RespChameleonHash
	senddata, _ := json.Marshal(&rch)
	_, _, errs := gorequest.New().Post(url + "new_chameleonhash").
		Send(senddata).
		EndStruct(&result)
	if errs != nil {
		//err := fmt.Errorf("requestKeyPair %s error: %q", url, errs)
		//return KeyPair{}, err
		return RespChameleonHash{CHash: RandValue(), R: RandValue()}, nil
	}
	return result, nil
}

//UpdateChameleonHash 申请新的秘钥对
func UpdateChameleonHash(rch ReqChameleonHash) (string, error) {
	var result string
	senddata, _ := json.Marshal(&rch)
	_, _, errs := gorequest.New().Post(url + "update_chameleonhash").
		Send(senddata).
		EndStruct(&result)
	if errs != nil {
		//err := fmt.Errorf("requestKeyPair %s error: %q", url, errs)
		//return KeyPair{}, err
		return RandValue(), nil
	}
	return result, nil
}
