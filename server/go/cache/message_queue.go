package cache

import (
	"bufio"
	"fmt"
	"net"
	"strings"
)

func startServer(port string, queue chan<- string) {
	listener, err := net.Listen("tcp", port)
	if err != nil {
		panic(err)
	}
	defer listener.Close()
	fmt.Printf("Listening on %s\n", port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Accept error:", err)
			continue
		}
		go handleConnection(conn, queue)
	}
}

func handleConnection(conn net.Conn, queue chan<- string) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	data, _ := reader.ReadString('\n')
	logger.Infof("Received data: %s", data)
	queue <- strings.TrimSpace(data)
}
