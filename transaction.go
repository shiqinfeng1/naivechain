package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/cbergoon/merkletree"
	"github.com/shiqinfeng1/naivechain/utiles"
)

//RawTransaction 交易
type RawTransaction struct {
	From  string `json:"from"`
	To    string `json:"to"`
	Value string `json:"value"`
	Data  string `json:"data"`
}

//Transaction 交易
type Transaction struct {
	RawTransaction
	R             string `json:"r"`
	ChameleonHash string `json:"chameleonHash"`
}

//Size 计算长度
func (t *Transaction) Size() int {
	return len(t.From) + len(t.To) + len(t.Value) + len(t.Data) + len(t.R)
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

	if t.ChameleonHash != "" {
		return hex.DecodeString(t.ChameleonHash)
	}
	latestBlock := getLatestBlock()
	//获取最新高度的下一块的stage
	var keys []string
	pks := allPubKeyByStage(int(latestBlock.BlockNumber+1) / cycle)
	for _, k := range pks {
		keys = append(keys, k.PubKey)
	}
	tx, _ := json.Marshal(&RawTransaction{From: t.From, To: t.To, Value: t.Value, Data: t.Data})
	rch := utiles.ReqChameleonHash{
		PubKeys: keys,
		RawMsg:  string(tx),
		R:       t.R,
	}
	result, err := utiles.RequestChameleonHash(rch)
	if err != nil {
		return []byte{}, err
	}
	t.ChameleonHash = result.CHash
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

//TxnFilter 查询过滤条件
type TxnFilter struct {
	From  string `json:"from"`
	To    string `json:"to"`
	Value string `json:"value"`
	Start string `json:"start"`
	End   string `json:"end"`
}

//TxnSelector 交易删除条件
type TxnSelector struct {
	BlockNumber int `json:"blocknumber"`
	Index       int `json:"index"`
}

//TxnDesc 交易描述
type TxnDesc struct {
	Transaction   Transaction `json:"transaction"`
	MinedBlock    int         `json:"minedBlock"`
	MinedTime     string      `json:"minedtime"`
	ChameleonHash string      `json:"chameleonHash"`
}

//IndexedTransaction 交易
type IndexedTransaction struct {
	Txn   Transaction `json:"Txn"`
	Index int         `json:"index"`
}

func (t *IndexedTransaction) String() string {
	// return fmt.Sprintf("from:%s,to:%s,value:%s,data:%s",
	// 	t.From, t.To, t.Value, t.Data)
	s, _ := json.Marshal(t)
	return string(s)
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
			var txn IndexedTransaction
			json.Unmarshal([]byte(tx), &txn)
			start, _ := time.Parse(format, t.Start)
			end, _ := time.Parse(format, t.End)
			blocktime := time.Unix(int64(block.Timestamp), 0)
			match :=
				(t.From == "" || (t.From != "" && t.From == txn.Txn.From)) &&
					(t.To == "" || (t.To != "" && t.To == txn.Txn.To)) &&
					(t.Value == "" || (t.Value != "" && t.Value == txn.Txn.Value)) &&
					(t.Start == "" || (t.Start != "" && start.Before(blocktime))) &&
					(t.End == "" || (t.End != "" && end.After(blocktime)))
			if match {
				chash, _ := txn.Txn.CalculateHash()
				matched = append(matched,
					TxnDesc{Transaction: txn.Txn,
						MinedBlock:    n,
						MinedTime:     blocktime.Format(format),
						ChameleonHash: hex.EncodeToString(chash)})
			}
		}
	}
	return matched
}
func saveKeyPair(pk *KeyPairInfo) {
	//如果是重复的pubkey， 更新为最新
	for _, pubKey := range keypairinfos {
		if pk.Stage == pubKey.Stage && pk.NodeName == pubKey.NodeName {
			return
		}
	}
	keypairinfos = append(keypairinfos, *pk)
}
func updateKeyPair(pk *KeyPairInfo) {
	//如果是重复的pubkey， 更新为最新
	for n, pubKey := range keypairinfos {
		if pk.Stage == pubKey.Stage && pk.NodeName == pubKey.NodeName {
			keypairinfos[n].PubKey = pk.PubKey
			keypairinfos[n].PrivKey = pk.PrivKey
			return
		}
	}
	keypairinfos = append(keypairinfos, *pk)
}
func allPubKeyByStage(stage int) []KeyPairInfo {
	var pks []KeyPairInfo
	for _, pubKey := range keypairinfos {
		if stage == pubKey.Stage {
			pubKey.PrivKey = "" //发送的公钥中不包含私钥
			pks = append(pks, pubKey)
		}
	}
	return pks
}
func allPrivKeyByStage(stage int) []KeyPairInfo {
	var pks []KeyPairInfo
	for _, keypair := range keypairinfos {
		if stage == keypair.Stage {
			pks = append(pks, keypair)
		}
	}
	return pks
}
func allPubKeyByNode(nodeName string) []KeyPairInfo {
	var pks []KeyPairInfo
	for _, pubKey := range keypairinfos {
		if nodeName == pubKey.NodeName {
			pubKey.PrivKey = "" //发送的公钥中不包含私钥
			pks = append(pks, pubKey)
		}
	}
	return pks
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
	for n, t := range list {
		hash, _ := t.CalculateHash()
		all[n].ChameleonHash = hex.EncodeToString(hash)
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
	index := 0
	var txn IndexedTransaction
	for _, t := range all {
		txn.Txn = *t
		txn.Index = index
		txns = append(txns, txn.String())
		index++
	}
	return txns
}

func delTxnProposal(txnSelector TxnSelector, done chan error) {
	var votedAll bool
	stage := txnSelector.BlockNumber / cycle

	//检查是否收到指定阶段的私钥
	queryPrivKey := func() (privkeys []KeyPairInfo) {
		votedAll = true
		for _, keypair := range keypairinfos {
			if stage == keypair.Stage {
				if keypair.PrivKey == "" {
					//还有peer未发送私钥过来
					votedAll = false
				}
				privkeys = append(privkeys, keypair)
			}
		}
		return
	}

	//1s检查一次私钥,超过10s则超时返回不在检查
	count := 10
	c := time.Tick(time.Duration(1) * time.Second)
	for {
		privkeys := queryPrivKey()
		if votedAll == true {
			break
		}
		count--
		if count == 0 {
			done <- fmt.Errorf("Wait Priv Key Timeout: %+v", privkeys)
			return
		}
		<-c
	}

	//获取删除交易后的新的r
	reqHash := func() error {
		//获取对应stage的所有私钥
		var keys []string
		pks := allPrivKeyByStage(stage)
		for _, k := range pks {
			keys = append(keys, k.PrivKey)
		}
		//遍历区块中的所有交易,找到指定交易
		for i, txOld := range blockchain[txnSelector.BlockNumber].Txns {
			var txn IndexedTransaction
			json.Unmarshal([]byte(txOld), &txn)

			if txn.Index == txnSelector.Index {

				//请求计算删除后的交易的r
				tx, _ := json.Marshal(&RawTransaction{From: txn.Txn.From, To: txn.Txn.To, Value: txn.Txn.Value, Data: txn.Txn.Data})
				rch := utiles.ReqChameleonHash{
					PubKeys: keys,
					RawMsg:  string(tx),
					R:       txn.Txn.R,
				}
				result, err := utiles.UpdateChameleonHash(rch)
				if err != nil {
					return err
				}
				//生成新的交易，并替换旧交易
				txn.Txn = Transaction{R: result, ChameleonHash: txn.Txn.ChameleonHash}
				blockchain[txnSelector.BlockNumber].Txns[i] = txn.String()
				return nil
			}
		}
		return fmt.Errorf("Not Found Required Txn")
	}

	if err := reqHash(); err != nil {
		done <- err
		return
	}
	done <- nil
	return
}
