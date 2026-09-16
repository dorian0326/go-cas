package main

import "github.com/dorian0326/go-cas/p2p"

func makeServr(listenAddr string, nodes ...string) *FileServer {
	tcptransportOpts := p2p.TCPTransportOpts{
		ListenAddr:    listenAddr,
		HandshakeFunc: p2p.NOPHandshakeFunc,
		Decoder:       p2p.DefaultDecoder{},
	}
	tcpTransport := p2p.NewTCPTransport(tcptransportOpts)

	fileServer := NewFileServer(fileServerOpts)
	return fileServer
}

func main() {

}
