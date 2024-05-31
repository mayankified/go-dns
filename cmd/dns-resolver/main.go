package main

import (
	"fmt"
	"github.com/mayankified/go-dns/pkg/dns"
	"net"
)

const (
	MaxPacketSize = 512
	Port          = ":8053"
)

func main() {
	asciiArt := `
▄▄▄█████▓ ██▓ ███▄    █  █    ██    ▓█████▄  ███▄    █   ██████ 
▓  ██▒ ▓▒▓██▒ ██ ▀█   █  ██  ▓██▒   ▒██▀ ██▌ ██ ▀█   █ ▒██    ▒ 
▒ ▓██░ ▒░▒██▒▓██  ▀█ ██▒▓██  ▒██░   ░██   █▌▓██  ▀█ ██▒░ ▓██▄   
░ ▓██▓ ░ ░██░▓██▒  ▐▌██▒▓▓█  ░██░   ░▓█▄   ▌▓██▒  ▐▌██▒  ▒   ██▒
  ▒██▒ ░ ░██░▒██░   ▓██░▒▒█████▓    ░▒████▓ ▒██░   ▓██░▒██████▒▒
  ▒ ░░   ░▓  ░ ▒░   ▒ ▒ ░▒▓▒ ▒ ▒     ▒▒▓  ▒ ░ ▒░   ▒ ▒ ▒ ▒▓▒ ▒ ░
    ░     ▒ ░░ ░░   ░ ▒░░░▒░ ░ ░     ░ ▒  ▒ ░ ░░   ░ ▒░░ ░▒  ░ ░
  ░       ▒ ░   ░   ░ ░  ░░░ ░ ░     ░ ░  ░    ░   ░ ░ ░  ░  ░  
          ░           ░    ░           ░             ░       ░  
                                     ░                          
	`
	fmt.Print(asciiArt)
	fmt.Printf("Starting DNS Server...\n")
	packetconn, err := net.ListenPacket("udp", Port)
	if err != nil {
		panic(err)
	}
	defer packetconn.Close()
	for {
		buff := make([]byte, MaxPacketSize)
		bytenum, addr, err := packetconn.ReadFrom(buff)
		if err != nil {
			fmt.Printf("Read Error from %s : %s \n", addr.String(), err)
			continue
		}
		go dns.HandlePacket(packetconn, addr, buff[:bytenum])
	}

}
