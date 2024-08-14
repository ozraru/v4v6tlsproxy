package internal

import (
	"context"
	"log"
	"net"
)

func Listen(ctx context.Context) {
	listenAddr, err := net.ResolveTCPAddr("tcp4", Config.Network.ListenAddress)
	if err != nil {
		log.Panic("Failed to parse listen address: ", err)
	}
	listener, err := net.ListenTCP("tcp4", listenAddr)
	if err != nil {
		log.Panic("Failed to make listener: ", err)
	}
	log.Print("Listening: ", listener.Addr())
	for {
		conn, err := listener.AcceptTCP()
		if err != nil {
			log.Panic("Failed to accept socket: ", err)
		}
		go handle(ctx, conn)
	}
}
