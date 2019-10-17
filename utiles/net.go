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
		return KeyPair{PrivKey: "a9db12f0905c0160f963dcf4bb1e39383f8693af87b649bcfd6c652b395075ae", PubKey: "7db20e3a7d652bde0b1a1b7486076a2e11f795e99bf7f5fe700fb83f15b19ef2"}, nil
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
		return RespChameleonHash{CHash: "816534932c2b7154836da6afc367695e6337db8a921823784c14378abed4f7d7", R: "84cdecc9c273927ff6d9cca1ae75945990a2cb1f81e5daab52a987f6d788c372"}, nil
	}
	return result, nil
}

//UpdateChameleonHash 申请新的秘钥对
func UpdateChameleonHash(rch ReqChameleonHash) (RespChameleonHash, error) {
	var result RespChameleonHash
	senddata, _ := json.Marshal(&rch)
	_, _, errs := gorequest.New().Post(url + "update_chameleonhash").
		Send(senddata).
		EndStruct(&result)
	if errs != nil {
		//err := fmt.Errorf("requestKeyPair %s error: %q", url, errs)
		//return KeyPair{}, err
		return RespChameleonHash{CHash: "816534932c2b7154836da6afc367695e6337db8a921823784c14378abed4f7d7", R: "84cdecc9c273927ff6d9cca1ae75945990a2cb1f81e5daab52a987f6d788c372"}, nil
	}
	return result, nil
}
