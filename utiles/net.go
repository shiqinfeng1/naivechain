package utiles

import (
	"encoding/json"
	"fmt"
	"log"
	"math/big"

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
}

var url = "http://localhost:8080/"

const (
	P = "ea14e4273bebe7fd2ab02d3f4075c29a8c891afa53a3c5cab9c1550e8e91c9bf"
	Q = "750a72139df5f3fe9558169fa03ae14d46448d7d29d1e2e55ce0aa874748e4df"
	G = "34eedb6f3da5a87a5d9a0baafe069e2f7958480bd6e4f8280181bac0f4d02cf6"
)

var PQG = "?p_hex=" + P + "&q_hex=" + Q + "&g_hex=" + G

//RequestPGQ 申请新的秘钥对
func RequestPGQ() ([3]string, error) {
	var result [3]string
	_, body, errs := gorequest.New().Get(url + "lvweilong/setUp").EndBytes()
	if errs != nil {
		err := fmt.Errorf("RequestPGQ %s error: %q", url, errs)
		return [3]string{}, err
	}
	err := json.Unmarshal(body, &result)
	return result, err
}

//RequestKeyPair 申请新的秘钥对
func RequestKeyPair() (KeyPair, error) {
	var result [2]string
	_, body, errs := gorequest.New().Get(url + "lvweilong/keyGen" + PQG).EndBytes()
	if errs != nil {
		err := fmt.Errorf("request KeyPair %s error: %q", url, errs)
		return KeyPair{}, err
		//return KeyPair{PrivKey: RandValue(), PubKey: RandValue()}, nil
	}
	err := json.Unmarshal(body, &result)
	return KeyPair{PrivKey: result[0], PubKey: result[1]}, err
}

//RequestChameleonHash 计算hash
func RequestChameleonHash(rch ReqChameleonHash) (RespChameleonHash, error) {

	Pub := big.NewInt(1)
	for _, v := range rch.PubKeys {
		big1, _ := new(big.Int).SetString(v, 16)
		Pub.Mul(Pub, big1)
	}
	req := url + "lvweilong/Hash" + PQG + "&h_hex=" + fmt.Sprintf("%x", Pub) + "&m_str=" + rch.RawMsg + "&r_hex=" + rch.R

	_, body, errs := gorequest.New().Get(req).EndBytes()
	if errs != nil {
		err := fmt.Errorf("Request ChameleonHash %s error: %q", url, errs)
		return RespChameleonHash{}, err
		//return RespChameleonHash{CHash: RandValue()}, nil
	}
	log.Println("Request ChameleonHash:", req, "-->", string(body))
	return RespChameleonHash{CHash: string(body)}, nil
}

//UpdateChameleonHash 申请新的秘钥对
func UpdateChameleonHash(rch ReqChameleonHash) (string, error) {

	Priv := big.NewInt(1)
	for _, v := range rch.PubKeys {
		big1, _ := new(big.Int).SetString(v, 16)
		Priv.Mul(Priv, big1)
	}
	req := url + "lvweilong/Forge" + PQG + "&x_hex=" + fmt.Sprintf("%x", Priv) + "&m_str=" + rch.RawMsg + "&m_new_str=&r_hex=" + rch.R

	_, body, errs := gorequest.New().Post(req).EndBytes()
	if errs != nil {
		err := fmt.Errorf("Update ChameleonHash %s error: %q", url, errs)
		return "", err
	}
	log.Println("Update ChameleonHash:", req, "-->", string(body))
	return string(body), nil
}
