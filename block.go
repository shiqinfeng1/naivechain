package main

import "fmt"

var genesisBlock = &Block{
	BlockNumber:  0,
	PreviousHash: "0",
	Timestamp:    1465154705,
	Txns:         []string{},
	Miner:        "my genesis block!!",
	Hash:         "816534932c2b7154836da6afc367695e6337db8a921823784c14378abed4f7d7",
	TxnRoot:      "",
}

//Block 区块
type Block struct {
	BlockNumber  int64    `json:"blockNumber"`
	PreviousHash string   `json:"previousHash"`
	Timestamp    int64    `json:"timestamp"`
	Txns         []string `json:"txns"`
	Miner        string   `json:"miner"`
	Hash         string   `json:"hash"`
	TxnRoot      string   `json:"txnRoot"`
}

//Size 计算长度
func (b *Block) Size() int {
	return 2 + len(b.PreviousHash) + 2 + len(b.Miner) + len(b.Hash) + len(b.TxnRoot) //+ len(b.Txns)*8
}

func (b *Block) String() string {
	return fmt.Sprintf("BlockNumber: %d,PreviousHash:%s,Timestamp:%d,txns:%v Miner:%s,Hash:%s,TxnRoot:%s",
		b.BlockNumber, b.PreviousHash, b.Timestamp, b.Txns, b.Miner, b.Hash, b.TxnRoot)
}

//ByIndex 区块
type ByIndex []*Block

func (b ByIndex) Len() int           { return len(b) }
func (b ByIndex) Swap(i, j int)      { b[i], b[j] = b[j], b[i] }
func (b ByIndex) Less(i, j int) bool { return b[i].BlockNumber < b[j].BlockNumber }
