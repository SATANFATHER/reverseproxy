package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings" // Added for error string checking in relay
)

const (
	socks5Version = 0x05
	noAuth        = 0x00
	userPassAuth  = 0x02
	ipv4Addr      = 0x01
	domainAddr    = 0x03
	connectCmd    = 0x01
)

func main() {
	host := "0.0.0.0"
	port := "1080"
	username := ""
	password := ""

	if len(os.Args) > 1 {
		host = os.Args[1]
	}
	if len(os.Args) > 2 {
		port = os.Args[2]
	}
	if len(os.Args) > 3 {
		username = os.Args[3]
	}
	if len(os.Args) > 4 {
		password = os.Args[4]
	}

	listenAddr := net.JoinHostPort(host, port)
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", listenAddr, err)
	}
	defer listener.Close()

	log.Printf("SOCKS5 proxy server started on %s", listenAddr)
	if username != "" && password != "" {
		log.Println("Authentication: User/Password enabled")
	} else {
		log.Println("Authentication: No Authentication")
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}
		go handleConnection(conn, username, password)
	}
}

func handleConnection(conn net.Conn, serverUser, serverPass string) {
	defer conn.Close()
	log.Printf("New connection from %s", conn.RemoteAddr())

	// Read client greeting
	// VER | NMETHODS | METHODS
	buf := make([]byte, 257) // Max methods is 255 + VER + NMETHODS
	n, err := conn.Read(buf[:2]) // Read VER and NMETHODS
	if err != nil || n != 2 {
		log.Printf("Error reading client greeting VER/NMETHODS: %v", err)
		return
	}

	ver := buf[0]
	nMethods := buf[1]

	if ver != socks5Version {
		log.Printf("Unsupported SOCKS version: %x", ver)
		return
	}

	_, err = io.ReadFull(conn, buf[:nMethods])
	if err != nil {
		log.Printf("Error reading client methods: %v", err)
		return
	}

	clientMethods := buf[:nMethods]
	serverRequiresAuth := serverUser != "" && serverPass != ""
	chosenMethod := byte(0xFF) // Initialize to no acceptable methods

	if serverRequiresAuth {
		for _, method := range clientMethods {
			if method == userPassAuth {
				chosenMethod = userPassAuth
				break
			}
		}
	} else { // Server does not require auth
		for _, method := range clientMethods {
			if method == noAuth {
				chosenMethod = noAuth
				break
			}
		}
	}

	// Send chosen method
	_, err = conn.Write([]byte{socks5Version, chosenMethod})
	if err != nil {
		log.Printf("Error sending chosen auth method: %v", err)
		return
	}

	if chosenMethod == 0xFF {
		log.Printf("No acceptable authentication method found for client %s", conn.RemoteAddr())
		return
	}

	if chosenMethod == userPassAuth {
		err = authenticateClient(conn, serverUser, serverPass)
		if err != nil {
			log.Printf("Client authentication failed: %v", err)
			// Optionally send an auth failure response, though SOCKS5 spec says close connection for user/pass failure
			return
		}
		log.Printf("Client %s authenticated successfully", conn.RemoteAddr())
	} else if chosenMethod == noAuth {
		if serverRequiresAuth {
			log.Printf("Client %s offered No Auth, but server requires User/Pass. Closing connection.", conn.RemoteAddr())
			return
		}
		log.Printf("Proceeding with No Authentication for client %s", conn.RemoteAddr())
	}


	// If authentication is successful or not required
	err = handleRequest(conn)
	if err != nil {
		log.Printf("Error handling request for %s: %v", conn.RemoteAddr(), err)
	}
}

func authenticateClient(conn net.Conn, serverUser, serverPass string) error {
	// User/Pass subnegotiation version
	const userPassSubNegotiationVersion = 0x01

	// Read VER and ULEN
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return fmt.Errorf("failed to read auth request header: %w", err)
	}

	ver := header[0]
	uLen := int(header[1])

	if ver != userPassSubNegotiationVersion {
		// Send failure response: VER | STATUS (0x01 for general failure)
		_, wErr := conn.Write([]byte{userPassSubNegotiationVersion, 0x01})
		if wErr != nil {
			log.Printf("Failed to send auth failure (version mismatch) to %s: %v", conn.RemoteAddr(), wErr)
		}
		return fmt.Errorf("unsupported user/pass subnegotiation version: %x", ver)
	}

	// Read UNAME
	uname := make([]byte, uLen)
	if _, err := io.ReadFull(conn, uname); err != nil {
		// Send failure response
		_, wErr := conn.Write([]byte{userPassSubNegotiationVersion, 0x01})
		if wErr != nil {
			log.Printf("Failed to send auth failure (uname read) to %s: %v", conn.RemoteAddr(), wErr)
		}
		return fmt.Errorf("failed to read username: %w", err)
	}

	// Read PLEN
	pLenHeader := make([]byte, 1)
	if _, err := io.ReadFull(conn, pLenHeader); err != nil {
		// Send failure response
		_, wErr := conn.Write([]byte{userPassSubNegotiationVersion, 0x01})
		if wErr != nil {
			log.Printf("Failed to send auth failure (plen read) to %s: %v", conn.RemoteAddr(), wErr)
		}
		return fmt.Errorf("failed to read password length: %w", err)
	}
	pLen := int(pLenHeader[0])

	// Read PASSWD
	passwd := make([]byte, pLen)
	if _, err := io.ReadFull(conn, passwd); err != nil {
		// Send failure response
		_, wErr := conn.Write([]byte{userPassSubNegotiationVersion, 0x01})
		if wErr != nil {
			log.Printf("Failed to send auth failure (passwd read) to %s: %v", conn.RemoteAddr(), wErr)
		}
		return fmt.Errorf("failed to read password: %w", err)
	}

	clientUser := string(uname)
	clientPass := string(passwd)

	authStatus := byte(0x01) // Default to failure
	if clientUser == serverUser && clientPass == serverPass {
		authStatus = 0x00 // Success
		log.Printf("User %s authenticated successfully for %s", clientUser, conn.RemoteAddr())
	} else {
		log.Printf("Authentication failed for user %s from %s: credentials mismatch", clientUser, conn.RemoteAddr())
	}

	// Send authentication response: VER | STATUS
	_, err := conn.Write([]byte{userPassSubNegotiationVersion, authStatus})
	if err != nil {
		return fmt.Errorf("failed to send authentication status to %s: %w", conn.RemoteAddr(), err)
	}

	if authStatus != 0x00 {
		return errors.New("client authentication failed: credentials mismatch")
	}

	return nil
}

func handleRequest(conn net.Conn) error {
	// Read the request header: VER | CMD | RSV
	reqHeader := make([]byte, 3)
	if _, err := io.ReadFull(conn, reqHeader); err != nil {
		return fmt.Errorf("failed to read request header: %w", err)
	}

	ver := reqHeader[0]
	cmd := reqHeader[1]
	// rsv := reqHeader[2] // Reserved, should be 0x00

	if ver != socks5Version {
		sendReply(conn, 0x01, nil, 0) // General SOCKS server failure
		return fmt.Errorf("unsupported SOCKS version in request: %x", ver)
	}

	if cmd != connectCmd {
		sendReply(conn, 0x07, nil, 0) // Command not supported
		return fmt.Errorf("unsupported command: %x", cmd)
	}

	// Read ATYP (Address Type)
	addrTypeByte := make([]byte, 1)
	if _, err := io.ReadFull(conn, addrTypeByte); err != nil {
		sendReply(conn, 0x01, nil, 0) // General SOCKS server failure
		return fmt.Errorf("failed to read address type: %w", err)
	}
	addrType := addrTypeByte[0]

	var dstAddr string
	var dstPortRaw []byte

	switch addrType {
	case ipv4Addr:
		addrBytes := make([]byte, 4)
		if _, err := io.ReadFull(conn, addrBytes); err != nil {
			sendReply(conn, 0x01, nil, 0)
			return fmt.Errorf("failed to read IPv4 address: %w", err)
		}
		dstAddr = net.IP(addrBytes).String()
	case domainAddr:
		lenByte := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenByte); err != nil {
			sendReply(conn, 0x01, nil, 0)
			return fmt.Errorf("failed to read domain length: %w", err)
		}
		domainLen := int(lenByte[0])
		domainBytes := make([]byte, domainLen)
		if _, err := io.ReadFull(conn, domainBytes); err != nil {
			sendReply(conn, 0x01, nil, 0)
			return fmt.Errorf("failed to read domain name: %w", err)
		}
		dstAddr = string(domainBytes)
	default: // Includes IPv6 (0x04) and any other unsupported types
		sendReply(conn, 0x08, nil, 0) // Address type not supported
		return fmt.Errorf("unsupported address type: %x", addrType)
	}

	// Read DST.PORT (2 bytes, network byte order)
	dstPortRaw = make([]byte, 2)
	if _, err := io.ReadFull(conn, dstPortRaw); err != nil {
		sendReply(conn, 0x01, nil, 0)
		return fmt.Errorf("failed to read destination port: %w", err)
	}
	dstPort := uint16(dstPortRaw[0])<<8 | uint16(dstPortRaw[1])

	targetAddr := net.JoinHostPort(dstAddr, strconv.Itoa(int(dstPort)))
	log.Printf("Client %s requests connection to %s", conn.RemoteAddr(), targetAddr)

	// Resolve domain name if necessary (dial will do this, but good to be aware)
	// For SOCKS reply, we might need the resolved IP.
	// However, the spec says BND.ADDR is server-side IP, not necessarily resolved IP of target.

	destConn, err := net.Dial("tcp", targetAddr)
	if err != nil {
		// Determine reply code based on error type
		replyCode := byte(0x01) // General SOCKS server failure by default
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			replyCode = 0x04 // Host unreachable (could also be network unreachable)
		} else if opError, ok := err.(*net.OpError); ok {
			if opError.Op == "dial" {
				// syscall.ECONNREFUSED typically
				if sysErr, ok := opError.Err.(*os.SyscallError); ok && sysErr.Err.Error() == "connection refused" {
					replyCode = 0x05 // Connection refused
				} else {
					replyCode = 0x04 // Host unreachable (generic dial error)
				}
			}
		}
		// Potentially more specific error mapping here
		log.Printf("Failed to connect to destination %s: %v", targetAddr, err)
		sendReply(conn, replyCode, nil, 0)
		return fmt.Errorf("failed to dial destination %s: %w", targetAddr, err)
	}
	defer destConn.Close()
	log.Printf("Successfully connected to %s for client %s", targetAddr, conn.RemoteAddr())

	// Send success reply
	// BND.ADDR and BND.PORT should be the address and port of the server *as seen from the client's perspective*
	// for the connection to the target. Often, using 0.0.0.0 and the listening port is acceptable,
	// or the local address of the `destConn`.
	// For simplicity, we'll use 0.0.0.0 and the original port requested if it was IPv4/Domain.
	// The SOCKS RFC is a bit vague on BND.ADDR/PORT for CONNECT; some implementations use the
	// local address of the outgoing connection (destConn.LocalAddr()).
	// Let's use the destConn.LocalAddr() as it's more accurate for the bound address.

	bndAddr, bndPortNum, err := net.SplitHostPort(destConn.LocalAddr().String())
	if err != nil {
		sendReply(conn, 0x01, nil, 0) // General SOCKS server failure
		return fmt.Errorf("failed to parse destConn local address: %w", err)
	}
	bndPort, _ := strconv.Atoi(bndPortNum) // Error already handled by SplitHostPort typically

	var bndIPBytes []byte
	// var replyAddrType byte // This variable is unused as sendReply determines addrType internally

	parsedBndIP := net.ParseIP(bndAddr)
	if parsedBndIP == nil { // Should not happen with LocalAddr()
	    sendReply(conn, 0x01, nil, 0)
	    return fmt.Errorf("failed to parse bind address IP: %s", bndAddr)
	}

	if parsedBndIP.To4() != nil {
		bndIPBytes = parsedBndIP.To4()
		// replyAddrType = ipv4Addr // Unused
	} else {
		// This case should ideally not be hit if we only dial IPv4/Domain
		// but if destConn.LocalAddr() somehow returns an IPv6 on a system
		// that prefers it, we might need to handle it.
		// For now, send general failure if it's not IPv4, as our constants are IPv4/Domain.
		// Or, we could send 0.0.0.0 (IPv4) as a generic placeholder if allowed by spec.
		// Let's stick to sending what we got if it's IPv4, else error for now.
		// A robust server might return the IPv6 if ATYP 0x04 was defined and used.
		log.Printf("Warning: Bound address %s is not IPv4, sending 0.0.0.0", bndAddr)
		bndIPBytes = net.IPv4zero.To4() // Default to 0.0.0.0
		// replyAddrType = ipv4Addr // Unused
	}


	if err := sendReply(conn, 0x00, bndIPBytes, uint16(bndPort)); err != nil {
		return fmt.Errorf("failed to send success reply: %w", err)
	}

	// Relay data
	log.Printf("Relaying data between %s and %s", conn.RemoteAddr(), targetAddr)
	errChan := make(chan error, 2)

	go func() {
		_, err := io.Copy(destConn, conn)
		if err != nil && !errors.Is(err, io.EOF) && !strings.Contains(err.Error(), "use of closed network connection") {
			log.Printf("Error copying from client to destination: %v", err)
		}
		errChan <- err
	}()
	go func() {
		_, err := io.Copy(conn, destConn)
		if err != nil && !errors.Is(err, io.EOF) && !strings.Contains(err.Error(), "use of closed network connection") {
			log.Printf("Error copying from destination to client: %v", err)
		}
		errChan <- err
	}()

	// Wait for one of the copy operations to finish or error
	for i := 0; i < 2; i++ {
		if err := <-errChan; err != nil {
			// Don't return error for EOF or closed connection, as that's expected when a side closes
			if errors.Is(err, io.EOF) || strings.Contains(err.Error(), "use of closed network connection") {
				// log.Printf("EOF or closed connection during relay for %s: %v", conn.RemoteAddr(), err)
			} else {
				// return fmt.Errorf("data relay error: %w", err)
				// Log it but don't necessarily kill the other direction if it's still going.
				// The closing of connections by io.Copy will eventually terminate both.
				log.Printf("Data relay error for %s: %v", conn.RemoteAddr(), err)
			}
		}
	}
	log.Printf("Relay finished for %s", conn.RemoteAddr())
	return nil
}

// sendReply sends a SOCKS5 reply to the client.
// bndAddr should be the IP address bytes (e.g., 4 bytes for IPv4).
// bndPort should be in host byte order.
func sendReply(conn net.Conn, rep byte, bndAddr []byte, bndPort uint16) error {
	reply := []byte{socks5Version, rep, 0x00 /* RSV */}
	addrType := byte(ipv4Addr) // Default to IPv4 for now

	if bndAddr == nil {
		// If bndAddr is nil (e.g. for failures before address is known),
		// use 0.0.0.0 as placeholder.
		bndAddr = net.IPv4zero.To4()
		addrType = ipv4Addr
	} else {
		// Check if it's IPv4 or something else (e.g. if we support IPv6 replies later)
		// For now, this function assumes bndAddr is IPv4 if not nil.
		// If we pass an IPv6 address here, this logic would need to change.
		if len(bndAddr) == net.IPv6len {
			// addrType = ipv6Addr // If we had this constant and supported it
			// For now, force to IPv4 if we get IPv6, or handle error
			// This part of the code assumes we are sending an IPv4 bind address.
			// If bndAddr could be IPv6, we'd need an ipv6AddrType constant and logic.
			// Forcing it to IPv4zero if it's IPv6 for now.
			log.Printf("Warning: sendReply received IPv6 bind address, sending as IPv4 zero. This should be handled better.")
			bndAddr = net.IPv4zero.To4()
			addrType = ipv4Addr
		} else if len(bndAddr) == net.IPv4len {
			addrType = ipv4Addr
		} else {
			log.Printf("Error: sendReply received bndAddr of unexpected length %d, sending as IPv4 zero.", len(bndAddr))
			bndAddr = net.IPv4zero.To4()
			addrType = ipv4Addr
		}
	}


	reply = append(reply, addrType)
	reply = append(reply, bndAddr...)
	reply = append(reply, byte(bndPort>>8), byte(bndPort&0xFF))

	_, err := conn.Write(reply)
	if err != nil {
		log.Printf("Failed to send reply to %s: %v", conn.RemoteAddr(), err)
	}
	return err
}
