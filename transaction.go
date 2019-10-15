package main

import (
	"encoding/hex"
	"encoding/json"
	"log"
	"math/rand"
	"time"

	"github.com/cbergoon/merkletree"
	"github.com/shiqinfeng1/naivechain/utiles"
)

//Transaction 交易
type Transaction struct {
	From  string `json:"from"`
	To    string `json:"to"`
	Value string `json:"value"`
	Data  string `json:"data"`
	R     string `json:"r"`
}

//TxnFilter 查询过滤条件
type TxnFilter struct {
	From  string `json:"from"`
	To    string `json:"to"`
	Value string `json:"value"`
	Start string `json:"start"`
	End   string `json:"end"`
}

//TxnDesc 交易描述
type TxnDesc struct {
	Transaction   Transaction `json:"transaction"`
	MinedBlock    int         `json:"minedBlock"`
	MinedTime     string      `json:"minedtime"`
	ChameleonHash string      `json:"chameleonHash"`
}

func (t *Transaction) String() string {
	// return fmt.Sprintf("from:%s,to:%s,value:%s,data:%s",
	// 	t.From, t.To, t.Value, t.Data)
	s, _ := json.Marshal(t)
	return string(s)
}

//CalculateHash 计算hash
func (t Transaction) CalculateHash() ([]byte, error) {
	// h := sha256.New()
	// if _, err := h.Write([]byte(t.From + t.To + t.Value + t.Data)); err != nil {
	// 	return nil, err
	// }
	// return h.Sum(nil), nil
	latestBlock := getLatestBlock()
	//获取最新高度的下一块的stage
	var keys []string
	pks := allPubKeyByStage(int(latestBlock.Index+1) / cycle)
	for _, k := range pks {
		keys = append(keys, k.PubKey)
	}
	tx, _ := json.Marshal(&t)
	rch := utiles.ReqChameleonHash{
		PubKeys: keys,
		RawMsg:  string(tx),
	}
	result, err := utiles.RequestChameleonHash(rch)
	if err != nil {
		return []byte{}, err
	}
	return hex.DecodeString(result.CHash)
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
func queryTransaction(t *TxnFilter) []TxnDesc {
	var matched []TxnDesc
	format := "2006-01-02 15:04:05"
	//遍历所有区块
	for n, block := range blockchain {
		if len(block.Txns) == 0 {
			continue
		}
		//遍历区块中的所有交易
		for _, tx := range block.Txns {
			var txn Transaction
			json.Unmarshal([]byte(tx), &txn)
			start, _ := time.Parse(format, t.Start)
			end, _ := time.Parse(format, t.End)
			blocktime := time.Unix(int64(block.Timestamp), 0)
			match :=
				(t.From == "" || (t.From != "" && t.From == txn.From)) &&
					(t.To == "" || (t.To != "" && t.To == txn.To)) &&
					(t.Value == "" || (t.Value != "" && t.Value == txn.Value)) &&
					(t.Start == "" || (t.Start != "" && start.Before(blocktime))) &&
					(t.End == "" || (t.End != "" && end.After(blocktime)))
			if match {
				chash, _ := txn.CalculateHash()
				matched = append(matched,
					TxnDesc{Transaction: txn,
						MinedBlock:    n,
						MinedTime:     blocktime.Format(format),
						ChameleonHash: hex.EncodeToString(chash)})
			}
		}
	}
	return matched
}
func savePubKey(pk *PubKeyInfo) {
	//如果是重复的pubkey， 不更新
	for _, pubKey := range pubKeyinfos {
		if pk.Stage == pubKey.Stage && pk.NodeName == pubKey.NodeName {
			return
		}
	}
	pubKeyinfos = append(pubKeyinfos, *pk)
}

func allPubKeyByStage(stage int) []PubKeyInfo {
	var pks []PubKeyInfo
	for _, pubKey := range pubKeyinfos {
		if stage == pubKey.Stage {
			pks = append(pks, pubKey)
		}
	}
	return pks
}
func allPubKeyByNode(nodeName string) []PubKeyInfo {
	var pks []PubKeyInfo
	for _, pubKey := range pubKeyinfos {
		if nodeName == pubKey.NodeName {
			pks = append(pks, pubKey)
		}
	}
	return pks
}
func randValue() string {
	var r = make([]byte, 32)
	rand.Seed(time.Now().UnixNano())
	n, _ := rand.Read(r)
	if n == 32 {
		return hex.EncodeToString(r)
	}
	return ""
}
func getMerkleRoot(all []*Transaction) string {
	//Build list of Content to build tree
	var list []merkletree.Content

	if len(all) == 0 {
		return ""
	}

	for _, t := range all {
		list = append(list, t)
	}

	//Create a new Merkle Tree from the list of Content
	t, err := merkletree.NewTree(list)
	if err != nil {
		log.Fatal(err)
	}
	//Get the Merkle Root of the tree
	mr := t.MerkleRoot()
	return hex.EncodeToString(mr)
}

func allTxns() []*Transaction {
	if len(txnPool) == 0 {
		return []*Transaction{}
	}
	txnPoolCopy := txnPool
	//清空交易池
	txnPool = []*Transaction{}
	return txnPoolCopy
}

func formatAllTxns(all []*Transaction) []string {
	var txns []string
	for _, t := range all {
		txns = append(txns, t.String())
	}
	return txns
}
