package main

import (
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/shiqinfeng1/naivechain/utiles"
	"golang.org/x/net/websocket"
)

var (
	cycle        = 60
	sockets      []*websocket.Conn
	blockchain   = []*Block{genesisBlock}
	txnPool      []*Transaction
	keypairinfos = []KeyPairInfo{}
	superNode    = flag.Bool("supernode", false, "super node.")
	nodeName     = flag.String("nodename", "no name", "node name.")
	httpAddr     = flag.String("api", "", "api server address.")
	p2pAddr      = flag.String("p2p", "", "p2p server address.")
	initialPeers = flag.String("peers", "", "initial peers")
	interval     = flag.String("interval", "60", "senonds interval of mining block time.")
)

//ResponseBlockchain 节点交互通用数据结构
type ResponseBlockchain struct {
	Type string `json:"type"`
	Data string `json:"data"`
}

//KeyPairInfo 公钥存储结构
type KeyPairInfo struct {
	NodeName  string `json:"nodeName"`
	Stage     int    `json:"stage"`
	PubKey    string `json:"pubkey"`
	PrivKey   string `json:"privkey"`
	TimeStamp string `json:"timeStamp"`
}

func errFatal(msg string, err error) {
	if err != nil {
		log.Fatalln(msg, err)
	}
}

func connectToPeers(peersAddr []string) {
	for _, peer := range peersAddr {
		if peer == "" {
			continue
		}
		ws, err := websocket.Dial(peer, "", peer)
		if err != nil {
			log.Println("dial to peer", err)
			continue
		}
		initConnection(ws)
	}
}
func initConnection(ws *websocket.Conn) {
	go wsHandleP2P(ws)

	log.Println("query latest block.")
	ws.Write(queryLatestMsg())
}

func handleBlocks(w http.ResponseWriter, r *http.Request) {
	bs, _ := json.MarshalIndent(blockchain, "", "    ")
	w.Write(bs)
}
func handlePendings(w http.ResponseWriter, r *http.Request) {
	bs, _ := json.MarshalIndent(txnPool, "", "    ")
	w.Write(bs)
}
func handleMineBlock() {
	block := generateNextBlock(*nodeName)
	addBlock(block)
	broadcast(responseLatestMsg())
}
func handleSendTransaction(w http.ResponseWriter, r *http.Request) {
	var txn Transaction
	decoder := json.NewDecoder(r.Body)
	defer r.Body.Close()
	err := decoder.Decode(&txn)
	if err != nil {
		w.WriteHeader(http.StatusGone)
		log.Println("[API] invalid transaction data : ", err.Error())
		w.Write([]byte("invalid transaction data. " + err.Error() + "\n"))
		return
	}
	txn.R = randValue()
	addTransaction(&txn)
	broadcast(newTransactionMsg(txn))
}
func handleQueryTransaction(w http.ResponseWriter, r *http.Request) {
	var txnFilter TxnFilter
	decoder := json.NewDecoder(r.Body)
	defer r.Body.Close()
	err := decoder.Decode(&txnFilter)
	if err != nil {
		w.WriteHeader(http.StatusGone)
		log.Println("[API] invalid transaction data : ", err.Error())
		w.Write([]byte("invalid transaction data. " + err.Error() + "\n"))
		return
	}
	result := queryTransaction(&txnFilter)
	bs, _ := json.MarshalIndent(result, "", "    ")
	w.Write(bs)
}
func handlePeers(w http.ResponseWriter, r *http.Request) {
	var slice []string
	for _, socket := range sockets {
		if socket.IsClientConn() {
			slice = append(slice, strings.Replace(socket.LocalAddr().String(), "ws://", "", 1))
		} else {
			slice = append(slice, socket.Request().RemoteAddr)
		}
	}
	bs, _ := json.MarshalIndent(slice, "", "    ")
	w.Write(bs)
}

func handlekeypairs(w http.ResponseWriter, r *http.Request) {
	bs, _ := json.MarshalIndent(keypairinfos, "", "    ")
	w.Write(bs)
}
func handleDelTxn(w http.ResponseWriter, r *http.Request) {
	var txnSelector TxnSelector
	decoder := json.NewDecoder(r.Body)
	defer r.Body.Close()
	err := decoder.Decode(&txnSelector)
	if err != nil {
		w.WriteHeader(http.StatusGone)
		log.Println("[API] invalid delete transaction data : ", err.Error())
		w.Write([]byte("invalid delete transaction data. " + err.Error() + "\n"))
		return
	}
	//广播删除交易的提议
	broadcast(delTxnProposalMsg(txnSelector))
	//删除交易
	done := make(chan error)
	go delTxnProposal(txnSelector, done)
	//等待交易完成
	if err := <-done; err != nil {
		w.WriteHeader(http.StatusGone)
		log.Println("[API] delete transaction fail : ", err.Error())
		w.Write([]byte("delete transaction fail. " + err.Error() + "\n"))
		return
	}
	block := getBlock(txnSelector.BlockNumber)
	b, _ := json.MarshalIndent(block, "", "    ")
	w.Write([]byte("delete transaction success: " + string(b)))
	broadcast(updatedBlockMsg(*block))
}

func handleAddPeer(w http.ResponseWriter, r *http.Request) {
	var v struct {
		Peer string `json:"peer"`
	}
	decoder := json.NewDecoder(r.Body)
	defer r.Body.Close()
	err := decoder.Decode(&v)
	if err != nil {
		w.WriteHeader(http.StatusGone)
		log.Println("[API] invalid peer data : ", err.Error())
		w.Write([]byte("invalid peer data. " + err.Error()))
		return
	}
	connectToPeers(strings.Split(v.Peer, ",")) //[]string{v.Peer})
}

func wsHandleP2P(ws *websocket.Conn) {
	var (
		v    = &ResponseBlockchain{}
		peer = ws.LocalAddr().String()
	)
	sockets = append(sockets, ws)

	for {
		var msg []byte
		err := websocket.Message.Receive(ws, &msg)
		if err == io.EOF {
			log.Printf("p2p Peer[%s] shutdown, remove it form peers pool.\n", peer)
			break
		}
		if err != nil {
			log.Println("Can't receive p2p msg from ", peer, err.Error())
			break
		}
		//msgStr := utiles.Indent(msg)
		//log.Printf("Received[from %s]: %s.\n", peer, msgStr)
		err = json.Unmarshal(msg, v)
		errFatal("invalid p2p msg", err)

		switch v.Type {
		case "queryLatest":
			v.Type = "responseBlockchain"

			bs := responseLatestMsg()
			bsStr := utiles.Indent(bs)
			log.Printf("Response Latest Block: %s\n", bsStr)
			ws.Write(bs)

			//除了发送最新的区块数据外，还发送公钥和随机数
			log.Printf("Notify Latest PubKey...\n")
			ws.Write(pubKeyMsg(allPubKeyByNode(*nodeName)))

		case "queryAll":
			d, _ := json.Marshal(blockchain)
			v.Type = "responseBlockchain"
			v.Data = utiles.Indent(d)
			bs, _ := json.Marshal(v)
			bsStr := utiles.Indent(bs)
			log.Printf("Response Chain Data: %s\n", bsStr)
			ws.Write(bs)

		case "responseBlockchain":
			handleBlockchainResponse([]byte(v.Data))

		case "transaction":
			var txn Transaction
			err = json.Unmarshal([]byte(v.Data), &txn)
			errFatal("invalid transaction msg", err)
			addTransaction(&txn)

		case "mine":
			log.Printf("In-Turn To Mine ...\n")
			go handleMineBlock()

		case "pubKey":
			var pk []KeyPairInfo
			err = json.Unmarshal([]byte(v.Data), &pk)
			errFatal("invalid pubkey msg", err)
			for _, pubkey := range pk {
				saveKeyPair(&pubkey)
			}
		case "delTxnProposal":
			var selector TxnSelector
			var keyPairInfo KeyPairInfo
			err = json.Unmarshal([]byte(v.Data), &selector)
			errFatal("invalid del Txn Proposal msg", err)

			//找到需要的私钥
			for _, value := range keypairinfos {
				if selector.BlockNumber/cycle == value.Stage && *nodeName == value.NodeName {
					keyPairInfo = value
					break
				}
			}
			//回复私钥
			v.Type = "delTxnVote"
			data, _ := json.Marshal(keyPairInfo)
			v.Data = string(data)
			bs, _ := json.Marshal(v)
			bsStr := utiles.Indent(bs)
			log.Printf("Response delTxnVote Data: %s\n", bsStr)
			ws.Write(bs)

		case "delTxnVote":
			var keyPairInfo KeyPairInfo
			err = json.Unmarshal([]byte(v.Data), &keyPairInfo)
			errFatal("invalid del Txn Vote msg", err)
			//保存私钥
			updateKeyPair(&keyPairInfo)

		case "updateBlock":
			var block Block
			err = json.Unmarshal([]byte(v.Data), &block)
			errFatal("invalid updated block", err)
			updateBlock(block)
		}
	}
}
func getBlock(blocknumber int) (block *Block) {
	if blocknumber >= 0 && blocknumber < len(blockchain) {
		return blockchain[blocknumber]
	}
	return &Block{}
}
func updateBlock(block Block) error {
	if block.BlockNumber == 0 || block.BlockNumber >= int64(len(blockchain)) {
		return fmt.Errorf("block.BlockNumber Is Invalid:%v", block.BlockNumber)
	}
	if block.PreviousHash != blockchain[block.BlockNumber-1].Hash {
		return fmt.Errorf("block.PreviousHash Is Not Equal prev.Hash:%v preHash:%v", block.PreviousHash, blockchain[block.BlockNumber-1].Hash)
	}
	//更新的区块非最新高度的区块
	if block.BlockNumber < int64(len(blockchain)-1) &&
		block.Hash != blockchain[block.BlockNumber+1].PreviousHash {
		return fmt.Errorf("block.Hash Is Not Equal Next.prevHash:%v next.prevHash:%v", block.Hash, blockchain[block.BlockNumber+1].PreviousHash)
	}
	blockchain[block.BlockNumber] = &block
	return nil
}
func getLatestBlock() (block *Block) { return blockchain[len(blockchain)-1] }
func responseLatestMsg() (bs []byte) {
	var v = &ResponseBlockchain{Type: "responseBlockchain"}
	d, _ := json.Marshal(blockchain[len(blockchain)-1:])
	v.Data = string(d)
	bs, _ = json.Marshal(v)
	return
}
func newTransactionMsg(t Transaction) (bs []byte) {
	var v = &ResponseBlockchain{Type: "transaction"}
	d, _ := json.Marshal(t)
	v.Data = string(d)
	bs, _ = json.Marshal(v)
	return
}
func mineMsg() (bs []byte) {
	var v = &ResponseBlockchain{Type: "mine"}
	v.Data = ""
	bs, _ = json.Marshal(v)
	return
}
func pubKeyMsg(pk []KeyPairInfo) (bs []byte) {
	var v = &ResponseBlockchain{Type: "pubKey"}
	d, _ := json.Marshal(pk)
	v.Data = string(d)
	bs, _ = json.Marshal(v)
	return
}
func delTxnProposalMsg(selector TxnSelector) (bs []byte) {
	var v = &ResponseBlockchain{Type: "delTxnProposal"}
	sel, _ := json.Marshal(selector)
	v.Data = string(sel)
	bs, _ = json.Marshal(v)
	return bs
}
func updatedBlockMsg(block Block) (bs []byte) {
	var v = &ResponseBlockchain{Type: "updateBlock"}
	sel, _ := json.Marshal(block)
	v.Data = string(sel)
	bs, _ = json.Marshal(v)
	return bs
}
func queryLatestMsg() []byte { return []byte(fmt.Sprintf("{\"type\": %s}", "\"queryLatest\"")) }
func queryAllMsg() []byte    { return []byte(fmt.Sprintf("{\"type\": %s}", "\"queryAll\"")) }
func calculateHashForBlock(b *Block) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%d%s%d%s%s", b.BlockNumber, b.PreviousHash, b.Timestamp, b.Miner, b.TxnRoot))))
}
func generateNextBlock(data string) (nb *Block) {
	var previousBlock = getLatestBlock()
	txns := allTxns()
	root := getMerkleRoot(txns)
	nb = &Block{
		Miner:        data,
		Txns:         formatAllTxns(txns),
		PreviousHash: previousBlock.Hash,
		BlockNumber:  previousBlock.BlockNumber + 1,
		Timestamp:    time.Now().Unix(),
		TxnRoot:      root,
	}
	nb.Hash = calculateHashForBlock(nb)
	log.Printf("Mined Block: %+v\n", nb)
	return nb
}
func addBlock(b *Block) {
	if isValidNewBlock(b, getLatestBlock()) {
		blockchain = append(blockchain, b)
	}
}

func isValidNewBlock(nb, pb *Block) (ok bool) {
	if nb.Hash == calculateHashForBlock(nb) &&
		pb.BlockNumber+1 == nb.BlockNumber &&
		pb.Hash == nb.PreviousHash {
		ok = true
	}
	return
}
func isValidChain(bc []*Block) bool {
	if bc[0].String() != genesisBlock.String() {
		log.Println("No same GenesisBlock.", bc[0].String())
		return false
	}
	var temp = []*Block{bc[0]}
	for i := 1; i < len(bc); i++ {
		if isValidNewBlock(bc[i], temp[i-1]) {
			temp = append(temp, bc[i])
		} else {
			return false
		}
	}
	return true
}
func replaceChain(bc []*Block) {
	if isValidChain(bc) && len(bc) > len(blockchain) {
		log.Println("Received blockchain is valid. Replacing current blockchain with received blockchain.")
		blockchain = bc
		broadcast(responseLatestMsg())
	} else {
		log.Println("Received blockchain invalid.")
	}
}
func broadcast(msg []byte) {
	for n, socket := range sockets {
		_, err := socket.Write(msg)
		if err != nil {
			log.Printf("peer [%s] disconnected.", socket.RemoteAddr().String())
			sockets = append(sockets[0:n], sockets[n+1:]...)
		}
	}
}
func notify(index int, msg []byte) {
	_, err := sockets[index].Write(msg)
	if err != nil {
		log.Printf("peer [%s] disconnected.", sockets[index].RemoteAddr().String())
	}
}
func deleteMinedTxn(minedblocks []*Block) {

	if len(txnPool) == 0 {
		//log.Println("[deleteMinedTxn] No Txn in TxnPool.")
		return
	}
	//遍历收到的区块
	for b, block := range minedblocks {
		if len(block.Txns) == 0 {
			//log.Println("[deleteMinedTxn] No Txn in Block ", n, ".")
			continue
		}
		//遍历区块中的交易
		for _, tx := range block.Txns {
			//解析交易
			var txn IndexedTransaction
			json.Unmarshal([]byte(tx), &txn)
			//查找交易是否在交易池中
			for n, tx := range txnPool {
				if result, err := txn.Txn.Equals(*tx); err == nil {
					if result == true {
						txnPool = append(txnPool[0:n], txnPool[n+1:]...)
						log.Printf("Sync To Delete Mined Transaction In TxnPool Of Block %d.", b)
					}
				}
			}
		}
	}
}
func handleBlockchainResponse(msg []byte) {
	var receivedBlocks = []*Block{}

	err := json.Unmarshal(msg, &receivedBlocks)
	errFatal("invalid blockchain", err)

	log.Printf("Receive Synced Latest Block: %+v\n", receivedBlocks)
	sort.Sort(ByIndex(receivedBlocks))
	//删除本地交易池中已被打包的交易
	deleteMinedTxn(receivedBlocks)

	latestBlockReceived := receivedBlocks[len(receivedBlocks)-1]
	latestBlockHeld := getLatestBlock()
	if latestBlockReceived.BlockNumber > latestBlockHeld.BlockNumber {
		log.Printf("Blockchain Possibly Behind. We Got: %d Peer Got: %d", latestBlockHeld.BlockNumber, latestBlockReceived.BlockNumber)
		if latestBlockHeld.Hash == latestBlockReceived.PreviousHash {
			log.Println("We Can Append The Received Block To Our Chain.")
			blockchain = append(blockchain, latestBlockReceived)
		} else if len(receivedBlocks) == 1 {
			log.Println("We Have To Query The Chain From Our Peer.")
			broadcast(queryAllMsg())
		} else {
			log.Println("Received Blockchain Is Longer Than Current Blockchain.")
			replaceChain(receivedBlocks)
		}
	} else {
		log.Println("Received Blockchain Is Not Longer Than Current Blockchain. Do Nothing.")
	}
}

// 每隔60个块为一个阶段，每隔阶段使用不同的秘钥对，当还剩20块的时间时，更新下一个阶段的秘钥
func geneKeypair() {
	count := 0
	geneKeyPair := func() {
		kp, err := utiles.RequestKeyPair()
		if err != nil {
			log.Printf("[geneKeypair] fail. stage=%d err=%v", count/cycle, err)
			return
		}
		pk := &KeyPairInfo{
			NodeName:  *nodeName,
			Stage:     count / cycle,
			PubKey:    kp.PubKey,
			PrivKey:   kp.PrivKey,
			TimeStamp: time.Now().Format("2006-01-02 15:04:05")}
		saveKeyPair(pk)
		broadcast(pubKeyMsg(allPubKeyByNode(*nodeName)))
		log.Printf("[geneKeypair] Gene New keypair = %+v", pk)
		count += cycle
	}
	//定时通知出块
	go func() {
		t, _ := strconv.Atoi(*interval)
		c := time.Tick(time.Duration(int64(t)) * time.Second)
		for {
			//还未出块的时候 生成第1阶段（0-59）的秘钥对
			if len(blockchain) == 0 {
				geneKeyPair()
			} else { //伺候定时检查当前块高度，给每隔阶段生成新的秘钥对
				height := getLatestBlock().BlockNumber
				//如果高度较高，使得 count-height 为负数，需要生成秘钥对
				if count-int(height) < (cycle / 4) {
					geneKeyPair()
				}
			}
			<-c
		}
	}()
}

func notifyNodeMsg() {
	//定时通知出块
	count := 0
	go func() {
		t, _ := strconv.Atoi(*interval)
		c := time.Tick(time.Duration(int64(t)) * time.Second)
		for {
			<-c
			if len(sockets) == 0 {
				handleMineBlock()
				log.Println("In-Turn To Mine ...")
			} else {
				notify(count%len(sockets), mineMsg())
				//log.Println("[mine] Notify to mine block node index = ", count%len(sockets))
			}
			count++
		}
	}()
}
func main() {
	flag.Parse()
	log.Printf("####################\n")
	log.Printf("Current Node Name = %s. IsSuperNode = %v.\n", *nodeName, *superNode)
	log.Printf("####################\n")

	connectToPeers(strings.Split(*initialPeers, ","))

	http.HandleFunc("/blocks", handleBlocks)
	http.HandleFunc("/pendings", handlePendings)
	http.HandleFunc("/peers", handlePeers)
	http.HandleFunc("/keypairs", handlekeypairs)
	http.HandleFunc("/send_transaction", handleSendTransaction)
	http.HandleFunc("/query_transaction", handleQueryTransaction)
	http.HandleFunc("/add_peer", handleAddPeer)
	http.HandleFunc("/del_txn", handleDelTxn)

	go func() {
		log.Println("Listen HTTP on", *httpAddr)
		errFatal("start api server", http.ListenAndServe(*httpAddr, nil))
	}()
	if *superNode == true {
		notifyNodeMsg()
	}
	go geneKeypair()

	http.Handle("/", websocket.Handler(wsHandleP2P))
	log.Println("Listen P2P on ", *p2pAddr)
	errFatal("start p2p server", http.ListenAndServe(*p2pAddr, nil))
}
