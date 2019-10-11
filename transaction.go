package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/cbergoon/merkletree"
)

//Transaction 交易
type Transaction struct {
	From  string `json:"from"`
	To    string `json:"to"`
	Value string `json:"value"`
	Data  string `json:"data"`
}

func (t *Transaction) String() string {
	return fmt.Sprintf("from:%s,to:%s,value:%s,data:%s",
		t.From, t.To, t.Value, t.Data)
}

//CalculateHash 计算hash
func (t Transaction) CalculateHash() ([]byte, error) {
	h := sha256.New()
	if _, err := h.Write([]byte(t.From + t.To + t.Value + t.Data)); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

//Equals 比较是否相等
func (t Transaction) Equals(other merkletree.Content) (bool, error) {
	equ := (t.From == other.(Transaction).From) &&
		(t.To == other.(Transaction).To) &&
		(t.Value == other.(Transaction).Value) &&
		(t.Data == other.(Transaction).Data)
	return equ, nil
}

func addTransaction(t *Transaction) {
	txnPool = append(txnPool, t)
}
func savePubKey(pk *PubKey) {
	pubKeys[pk.Stage][pk.NodeName] = pk.PubKey
}
func allPubKey(stage int) []PubKey {
	var pks []PubKey
	for name, pubKey := range pubKeys[stage] {
		pks = append(pks, PubKey{NodeName: name, Stage: stage, PubKey: pubKey})
	}
	return pks
}
func getMerkleRoot() string {
	//Build list of Content to build tree
	var list []merkletree.Content

	if len(txnPool) == 0 {
		return ""
	}

	for _, t := range txnPool {
		list = append(list, t)
	}

	//Create a new Merkle Tree from the list of Content
	t, err := merkletree.NewTree(list)
	if err != nil {
		log.Fatal(err)
	}
	//Get the Merkle Root of the tree
	mr := t.MerkleRoot()
	log.Println(mr)
	return hex.EncodeToString(mr)
}
