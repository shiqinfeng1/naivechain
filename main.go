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
	sockets      []*websocket.Conn
	blockchain   = []*Block{genesisBlock}
	txnPool      []*Transaction
	pubKeys      = make(map[int]map[string]string)
	superNode    = flag.Bool("supernode", false, "super node.")
	nodeName     = flag.String("nodename", "no name", "node name.")
	httpAddr     = flag.String("api", "", "api server address.")
	p2pAddr      = flag.String("p2p", "", "p2p server address.")
	initialPeers = flag.String("peers", "", "initial peers")
	interval     = flag.String("interval", "60", "interval of mining block time.")
)

//ResponseBlockchain 节点交互通用数据结构
type ResponseBlockchain struct {
	Type string `json:"type"`
	Data string `json:"data"`
}

//PubKey PubKey
type PubKey struct {
	NodeName string `json:"nodeName"`
	Stage    int    `json:"stage"`
	PubKey   string `json:"pubkey"`
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
func handleTransaction(w http.ResponseWriter, r *http.Request) {
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
	addTransaction(&txn)
	broadcast(newTransactionMsg(txn))
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
		msgStr := utiles.Indent(msg)
		log.Printf("Received[from %s]: %s.\n", peer, msgStr)
		err = json.Unmarshal(msg, v)
		errFatal("invalid p2p msg", err)

		switch v.Type {
		case "queryLatest":
			v.Type = "responseBlockchain"

			bs := responseLatestMsg()
			bsStr := utiles.Indent(bs)
			log.Printf("responseLatestMsg: %s\n", bsStr)
			ws.Write(bs)

		case "queryAll":
			d, _ := json.MarshalIndent(blockchain, "", "    ")
			v.Type = "responseBlockchain"
			v.Data = string(d)
			bs, _ := json.MarshalIndent(v, "", "    ")
			bsStr := utiles.Indent(bs)
			log.Printf("responseChainMsg: %s\n", bsStr)
			ws.Write(bs)

		case "responseBlockchain":
			handleBlockchainResponse([]byte(v.Data))

		case "transaction":
			var txn Transaction
			err = json.Unmarshal([]byte(v.Data), &txn)
			errFatal("invalid transaction msg", err)
			addTransaction(&txn)

		case "mine":
			go handleMineBlock()

		case "pubKey":
			var pk PubKey
			err = json.Unmarshal([]byte(v.Data), &pk)
			errFatal("invalid pubkey msg", err)
			savePubKey(&pk)
		}
	}
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
func pubKeyMsg(pk *PubKey) (bs []byte) {
	var v = &ResponseBlockchain{Type: "pubKey"}
	d, _ := json.Marshal(pk)
	v.Data = string(d)
	bs, _ = json.Marshal(v)
	return
}
func queryLatestMsg() []byte { return []byte(fmt.Sprintf("{\"type\": %s}", "\"queryLatest\"")) }
func queryAllMsg() []byte    { return []byte(fmt.Sprintf("{\"type\": %s}", "\"queryAll\"")) }
func calculateHashForBlock(b *Block) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%d%s%d%s%s", b.Index, b.PreviousHash, b.Timestamp, b.ExtraData, b.TxnRoot))))
}
func generateNextBlock(data string) (nb *Block) {
	var previousBlock = getLatestBlock()
	root := getMerkleRoot()
	nb = &Block{
		ExtraData:    data,
		Txns:         allTxns(),
		PreviousHash: previousBlock.Hash,
		Index:        previousBlock.Index + 1,
		Timestamp:    time.Now().Unix(),
		TxnRoot:      root,
	}
	nb.Hash = calculateHashForBlock(nb)
	return
}
func addBlock(b *Block) {
	if isValidNewBlock(b, getLatestBlock()) {
		blockchain = append(blockchain, b)
	}
}

func allTxns() []string {
	var txns []string

	if len(txnPool) == 0 {
		return []string{}
	}
	txnPoolCopy := txnPool
	txnPool = []*Transaction{}
	for _, t := range txnPoolCopy {
		txns = append(txns, t.String())
	}
	return txns
}
func isValidNewBlock(nb, pb *Block) (ok bool) {
	if nb.Hash == calculateHashForBlock(nb) &&
		pb.Index+1 == nb.Index &&
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
func handleBlockchainResponse(msg []byte) {
	var receivedBlocks = []*Block{}

	err := json.Unmarshal(msg, &receivedBlocks)
	errFatal("invalid blockchain", err)

	sort.Sort(ByIndex(receivedBlocks))

	latestBlockReceived := receivedBlocks[len(receivedBlocks)-1]
	latestBlockHeld := getLatestBlock()
	if latestBlockReceived.Index > latestBlockHeld.Index {
		log.Printf("blockchain possibly behind. We got: %d Peer got: %d", latestBlockHeld.Index, latestBlockReceived.Index)
		if latestBlockHeld.Hash == latestBlockReceived.PreviousHash {
			log.Println("We can append the received block to our chain.")
			blockchain = append(blockchain, latestBlockReceived)
		} else if len(receivedBlocks) == 1 {
			log.Println("We have to query the chain from our peer.")
			broadcast(queryAllMsg())
		} else {
			log.Println("Received blockchain is longer than current blockchain.")
			replaceChain(receivedBlocks)
		}
	} else {
		log.Println("received blockchain is not longer than current blockchain. Do nothing.")
	}
}

// 每隔60个块为一个阶段，每隔阶段使用不同的秘钥对，当还剩20块的时间时，更新下一个阶段的秘钥
func updateKeypair() {
	count := 0

	geneKeyPair := func() {
		kp, _ := utiles.RequestKeyPair()
		pk := &PubKey{NodeName: *nodeName, Stage: count / 60, PubKey: kp.PubKey}
		savePubKey(pk)
		broadcast(pubKeyMsg(pk))
		count += 60
		log.Printf("[updateKeypair] update stage=%d key = %v", count/60, kp.PubKey)
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
				height := getLatestBlock().Index
				if count-int(height) < 20 {
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
				log.Println("[mine] Mine local...")
			} else {
				notify(count%len(sockets), mineMsg())
				log.Println("[mine] Notify to mine block node index = ", count%len(sockets))
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
	http.HandleFunc("/send_transaction", handleTransaction)
	http.HandleFunc("/pendings", handlePendings)
	http.HandleFunc("/peers", handlePeers)
	http.HandleFunc("/add_peer", handleAddPeer)
	go func() {
		log.Println("Listen HTTP on", *httpAddr)
		errFatal("start api server", http.ListenAndServe(*httpAddr, nil))
	}()
	if *superNode == true {
		notifyNodeMsg()
	}

	http.Handle("/", websocket.Handler(wsHandleP2P))
	log.Println("Listen P2P on ", *p2pAddr)
	errFatal("start p2p server", http.ListenAndServe(*p2pAddr, nil))
}
