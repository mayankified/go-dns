package dns

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"golang.org/x/net/dns/dnsmessage"
	"math/big"
	"net"
	"strings"
)

const ROOT_SERVERS = "198.41.0.4,199.9.14.201,192.33.4.12,199.7.91.13,192.203.230.10,192.5.5.241,192.112.36.4,198.97.190.53"

func HandlePacket(pc net.PacketConn, addr net.Addr, buff []byte) {
	if err := handlePacket(pc, addr, buff); err != nil {
		fmt.Printf("Handle Packet error %s : %s \n", addr.String(), err)

	}
}

func handlePacket(pc net.PacketConn, addr net.Addr, buff []byte) error {
	parser := dnsmessage.Parser{}
	header, err := parser.Start(buff)
	if err != nil {
		return err
	}
	que, err := parser.Question()
	if err != nil {
		return err
	}
	res, err := dnsQuery(getRootserver(), que)
	if err != nil {
		return err
	}
	res.Header.ID = header.ID

	resBuff, err := res.Pack()
	if err != nil {
		return err
	}
	_, err = pc.WriteTo(resBuff, addr)
	if err != nil {
		return err
	}

	return nil
}

func dnsQuery(servers []net.IP, que dnsmessage.Question) (*dnsmessage.Message, error) {

	fmt.Println("⏩ Resolving :", que.Name.String())

	for i := 0; i < 3; i++ {

		fmt.Println("\n🔍 Sending a DNS query to server level ", i+1)
		fmt.Println("📡 Servers: ", servers)

		dnsres, header, err := outgoingDnsQuery(servers, que)
		if err != nil {
			return nil, err
		}
		parsedres, err := dnsres.AllAnswers()
		if err != nil {
			return nil, err
		}
		if header.Authoritative {
			// fmt.Println("\n Authoritative response!: ", parsedres)
			// parsedres[0].Body.(*dnsmessage.AResource).A[:]
			fmt.Println("\n🎉 Authoritative response! : ", net.IP(parsedres[0].Body.(*dnsmessage.AResource).A[:]))
			// this is the IP address of the domain
			return &dnsmessage.Message{
				Header: dnsmessage.Header{
					Response: true,
				},
				Answers: parsedres,
			}, nil
		}
		Authoritative, err := dnsres.AllAuthorities()
		if err != nil {
			return nil, err
		}
		if len(Authoritative) == 0 {
			return &dnsmessage.Message{
					Header: dnsmessage.Header{RCode: dnsmessage.RCodeNameError},
				},
				nil
		}
		nameservers := make([]string, len(Authoritative))
		for _, authority := range Authoritative {
			if authority.Header.Type == dnsmessage.TypeNS {
				nameservers = append(nameservers, authority.Body.(*dnsmessage.NSResource).NS.String())
			}
		}

		additionals, err := dnsres.AllAdditionals()
		if err != nil {
			return nil, err
		}

		servers = []net.IP{}
		resolverfound := false
		for _, additional := range additionals {
			if additional.Header.Type == dnsmessage.TypeA {
				for _, nameserver := range nameservers {
					if additional.Header.Name.String() == nameserver {
						resolverfound = true
						servers = append(servers, additional.Body.(*dnsmessage.AResource).A[:])
					}

				}
			}
		}
		if !resolverfound {
			fmt.Println("No resolver found!")
			break
		}

	}
	return &dnsmessage.Message{
			Header: dnsmessage.Header{RCode: dnsmessage.RCodeServerFailure},
		},
		nil
}

func outgoingDnsQuery(servers []net.IP, question dnsmessage.Question) (*dnsmessage.Parser, *dnsmessage.Header, error) {

	max := ^uint16(0)
	//iska matlab pehle hum 16 bit ka zero number bana rhe fir usko "^" isse not karke 1111111 ke format me laa rhe usse humko max no. milega

	RandomId, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return nil, nil, err
	}
	message := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:       uint16(RandomId.Int64()),
			Response: false,
			OpCode:   dnsmessage.OpCode(0),
		},
		Questions: []dnsmessage.Question{question},
	}
	buff, err := message.Pack()
	if err != nil {
		return nil, nil, err
	}
	var connection net.Conn
	for _, server := range servers {
		connection, err = net.Dial("udp", server.String()+":53")
		if err == nil {
			break
		}
	}
	if connection == nil {
		return nil, nil, fmt.Errorf("failed to make Connection")
	}
	_, err = connection.Write(buff)
	if err != nil {
		return nil, nil, err
	}

	answer := make([]byte, 512)
	num, err := bufio.NewReader(connection).Read(answer)
	// fmt.Println("Number of bytes read from response:", num)

	if err != nil {
		return nil, nil, err
	}

	connection.Close()

	var parser dnsmessage.Parser
	header, err := parser.Start(answer[:num])
	if err != nil {
		return nil, nil, fmt.Errorf("parsing start error: %s", err)
	}

	que, err := parser.AllQuestions()
	if err != nil {
		return nil, nil, err
	}
	if len(que) != len(message.Questions) {
		return nil, nil, fmt.Errorf("answer packet has not same amt of que")
	}

	err = parser.SkipAllQuestions()
	if err != nil {
		return nil, nil, err
	}

	return &parser, &header, nil
}

func getRootserver() []net.IP {
	rootservers := []net.IP{}
	for _, rootserver := range strings.Split(ROOT_SERVERS, ",") {
		rootservers = append(rootservers, net.ParseIP(rootserver))
	}
	return rootservers
}
