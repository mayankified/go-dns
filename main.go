package main

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/time/rate"
	"log"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	MaxPacketSize = 512 // 512 bytes
	Port          = ":8053"
	ROOT_SERVERS  = "198.41.0.4,199.9.14.201,192.33.4.12,199.7.91.13,192.203.230.10,192.5.5.241,192.112.36.4,198.97.190.53"
	CacheDuration = 300 * time.Second // 5 minutes
)

// cache is a map of domains jo cache honge
var cache = struct {
	sync.RWMutex
	m map[string]cachedResponse
}{m: make(map[string]cachedResponse)}

// cachedResponse is a struct jo cache hoga
type cachedResponse struct {
	response *dnsmessage.Message
	expiry   time.Time
}

var (
	infolog     *log.Logger
	errorlog    *log.Logger
	rateLimiter = rate.NewLimiter(1, 5) // 5 requests per second

)

// init function to create log file
func init() {
	file, err := os.OpenFile("dns.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalln("Failed to open log file", err)
	}
	infolog = log.New(file, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
	errorlog = log.New(file, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)
}

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
	fmt.Println(asciiArt)
	fmt.Println("💡 Starting DNS Server!...💣                    🚬 Developed by: 𝗺  𝗮 𝘆 𝗮 𝗻 𝗸")
	fmt.Println("\n🔗 Listening on port", Port)
	infolog.Println("Starting DNS Server")

	// Listen for incoming UDP packets
	packetconn, err := net.ListenPacket("udp", Port)
	if err != nil {
		errorlog.Println("Error in listening to port", err)
		panic(err)
	}

	// Close the connection when the main function ends
	defer packetconn.Close()

	// Handle incoming packets
	for {
		buff := make([]byte, MaxPacketSize)
		// Incoming packets read kar rhe
		bytenum, addr, err := packetconn.ReadFrom(buff)
		if err != nil {
			fmt.Printf("Read Error from %s : %s \n", addr.String(), err)
			errorlog.Println("Read Error", err)
			continue
		}

		// Rate limit the incoming requests
		if !rateLimiter.Allow() {
			fmt.Println("Rate limit exceeded")
			errorlog.Println("Rate limit exceeded")
			continue
		}

		// Handle the incoming packet
		go HandlePacket(packetconn, addr, buff[:bytenum])

	}

}

func HandlePacket(pc net.PacketConn, addr net.Addr, buff []byte) {
	if err := processPacket(pc, addr, buff); err != nil {
		fmt.Printf("Handle Packet error %s : %s \n", addr.String(), err)
		errorlog.Println("Handle Packet error", err)

	}
}

// processPacket processes an incoming DNS packet
func processPacket(pc net.PacketConn, addr net.Addr, buff []byte) error {
	parser := dnsmessage.Parser{}

	// Start returns the header of the DNS message
	header, err := parser.Start(buff)
	if err != nil {
		errorlog.Println("Error parsing start", err)
		return err
	}

	// Question returns the question of the DNS message
	que, err := parser.Question()
	if err != nil {
		errorlog.Println("Error parsing question", err)
		return err
	}
	infolog.Println("Recieved query for", que.Name.String(), "from", addr.String(), "with ID", header.ID, "and type", que.Type.String())

	res, err := dnsQuery(getRootserver(), que)
	if err != nil {
		errorlog.Println("Error in dns query", err)
		return err
	}

	// Setting the ID of the response to the ID of the request
	res.Header.ID = header.ID

	cache.Lock()
	// Response ko cache me add kar rhe
	cache.m[que.Name.String()] = cachedResponse{
		response: res,
		expiry:   time.Now().Add(CacheDuration),
	}
	cache.Unlock()

	// Pack returns the DNS message as a byte slice
	resBuff, err := res.Pack()
	if err != nil {
		errorlog.Println("Error in packing response", err)
		return err
	}

	// writing the response to the connection
	_, err = pc.WriteTo(resBuff, addr)
	if err != nil {
		errorlog.Println("Error in writing response", err)
		return err
	}
	infolog.Println("Successfully responded for", que.Name.String(), "to", addr.String())

	return nil
}

// dnsQuery sends a DNS query to the specified servers
func dnsQuery(servers []net.IP, que dnsmessage.Question) (*dnsmessage.Message, error) {

	fmt.Println("\n ⏩ Resolving :", que.Name.String())
	infolog.Println("Resolving", que.Name.String())

	cache.RLock()
	// Check if the domain is already cached
	cached, ok := cache.m[que.Name.String()]
	cache.RUnlock()

	// If the domain is cached and the cache has not expired, return the cached response
	if ok && time.Now().Before(cached.expiry) {
		if len(cached.response.Answers) > 0 {

			fmt.Println("\n📚 Cache hit! 🎉", que.Name, "➡", net.IP(cached.response.Answers[0].Body.(*dnsmessage.AResource).A[:]))
			infolog.Println("Cache hit", que.Name.String())
		}
		return cached.response, nil
	}

	for i := 0; i < 3; i++ {

		// Get the type of server based on the iteration
		serverType := getServerType(i)
		fmt.Println("\n🔍 Sending a DNS query to ", serverType)
		infolog.Println("Sending a DNS query to", serverType)
		fmt.Println("📡 Servers: ", servers)
		infolog.Println("Servers", servers)

		// Send the DNS query to the servers
		dnsres, header, err := outgoingDnsQuery(servers, que)
		if err != nil {
			errorlog.Println("Error in outgoing DNS query", err)
			return nil, err
		}

		parsedres, err := dnsres.AllAnswers()
		if err != nil {
			errorlog.Println("Error in parsing response", err)
			return nil, err
		}

		// Check if the response is authoritative
		if header.Authoritative {

			fmt.Println("\n🎉 Authoritative response! : ", net.IP(parsedres[0].Body.(*dnsmessage.AResource).A[:]))

			infolog.Println("Authoritative response", que.Name.String(), "➡", net.IP(parsedres[0].Body.(*dnsmessage.AResource).A[:]))
			// this is the IP address of the domain
			res := &dnsmessage.Message{
				Header: dnsmessage.Header{
					Response: true,
				},
				Answers: parsedres,
			}
			cache.Lock()
			cache.m[que.Name.String()] = cachedResponse{
				response: res,
				expiry:   time.Now().Add(CacheDuration),
			}
			cache.Unlock()
			return res, nil
		}

		// Check if the response is a referral
		Authoritative, err := dnsres.AllAuthorities()
		if err != nil {
			errorlog.Println("Error in getting authorities", err)
			return nil, err
		}

		// If the response is a referral, get the nameservers
		if len(Authoritative) == 0 {
			return &dnsmessage.Message{
					Header: dnsmessage.Header{RCode: dnsmessage.RCodeNameError},
				},
				nil
		}

		// Get the nameservers from the referral
		nameservers := make([]string, len(Authoritative))
		for _, authority := range Authoritative {
			if authority.Header.Type == dnsmessage.TypeNS {
				nameservers = append(nameservers, authority.Body.(*dnsmessage.NSResource).NS.String())
			}
		}

		additionals, err := dnsres.AllAdditionals()
		if err != nil {
			errorlog.Println("Error in getting additionals", err)
			return nil, err
		}

		servers = []net.IP{}
		resolverfound := false

		// Get the IP addresses of the nameservers
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

		// If no resolver is found, break the loop
		if !resolverfound {
			fmt.Println("No resolver found!")
			infolog.Println("No resolver found")
			break
		}

	}

	// If the response is not authoritative, return a server failure
	return &dnsmessage.Message{
			Header: dnsmessage.Header{RCode: dnsmessage.RCodeServerFailure},
		},
		nil
}

func outgoingDnsQuery(servers []net.IP, question dnsmessage.Question) (*dnsmessage.Parser, *dnsmessage.Header, error) {

	max := ^uint16(0)
	//iska matlab pehle hum 16 bit ka zero number bana rhe fir usko "^" isse not karke 1111111 ke format me laa rhe usse humko max no. milega

	// RandomId is a random number between 0 and 65535
	RandomId, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		errorlog.Println("Error in generating random number", err)
		return nil, nil, err
	}

	// Create a DNS message
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
		errorlog.Println("Error in packing message", err)
		return nil, nil, err
	}

	// Create a connection to the server
	var connection net.Conn
	for _, server := range servers {
		connection, err = net.Dial("udp", server.String()+":53")
		if err == nil {
			break
		}
	}
	if connection == nil {
		errorlog.Println("Failed to make connection")
		return nil, nil, fmt.Errorf("failed to make Connection")
	}
	_, err = connection.Write(buff)
	if err != nil {
		errorlog.Println("Error in writing to connection", err)
		return nil, nil, err
	}

	// Read the response
	answer := make([]byte, 512)
	num, err := bufio.NewReader(connection).Read(answer)
	// fmt.Println("Number of bytes read from response:", num)

	if err != nil {
		errorlog.Println("Error in reading response", err)
		return nil, nil, err
	}

	connection.Close()

	var parser dnsmessage.Parser

	// Start returns the header of the DNS message
	header, err := parser.Start(answer[:num])
	if err != nil {
		errorlog.Println("Error in parsing start", err)
		return nil, nil, fmt.Errorf("parsing start error: %s", err)
	}
	// AllQuestions returns all the questions in the DNS message
	que, err := parser.AllQuestions()
	if err != nil {
		errorlog.Println("Error in getting all questions", err)
		return nil, nil, err
	}
	if len(que) != len(message.Questions) {
		errorlog.Println("Answer packet has not same amount of questions")
		return nil, nil, fmt.Errorf("answer packet has not same amt of que")
	}

	err = parser.SkipAllQuestions()
	if err != nil {
		errorlog.Println("Error in skipping all questions", err)
		return nil, nil, err
	}

	return &parser, &header, nil
}

// getRootserver returns the IP addresses of the root servers
func getRootserver() []net.IP {
	rootservers := []net.IP{}
	for _, rootserver := range strings.Split(ROOT_SERVERS, ",") {
		rootservers = append(rootservers, net.ParseIP(rootserver))
	}
	return rootservers
}

// getServerType returns the type of server based on the iteration
func getServerType(iteration int) string {
	switch iteration {
	case 0:
		return "Root Server"
	case 1:
		return "TLD Server"
	default:
		return "Authoritative Server"
	}
}
