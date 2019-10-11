package main

import "fmt"

var genesisBlock = &Block{
	Index:        0,
	PreviousHash: "0",
	Timestamp:    1465154705,
	Txns:         []string{},
	ExtraData:    "my genesis block!!",
	Hash:         "816534932c2b7154836da6afc367695e6337db8a921823784c14378abed4f7d7",
	TxnRoot:      "",
}

//Block 区块
type Block struct {
	Index        int64    `json:"index"`
	PreviousHash string   `json:"previousHash"`
	Timestamp    int64    `json:"timestamp"`
	Txns         []string `json:"txns"`
	ExtraData    string   `json:"extraData"`
	Hash         string   `json:"hash"`
	TxnRoot      string   `json:"txnRoot"`
}

func (b *Block) String() string {
	return fmt.Sprintf("index: %d,previousHash:%s,timestamp:%d,txns:%v data:%s,hash:%s",
		b.Index, b.PreviousHash, b.Timestamp, b.Txns, b.ExtraData, b.Hash)
}

//ByIndex 区块
type ByIndex []*Block

func (b ByIndex) Len() int           { return len(b) }
func (b ByIndex) Swap(i, j int)      { b[i], b[j] = b[j], b[i] }
func (b ByIndex) Less(i, j int) bool { return b[i].Index < b[j].Index }
