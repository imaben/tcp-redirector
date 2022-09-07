package main

import (
	"bufio"
	"io"
	"log"
	"net"
	"os"
	"strings"
)

func copyConn(src net.Conn, address string) {
	srcAddr := src.RemoteAddr().String()
	log.Printf("new connection. src:%s, dst:%s\n", srcAddr, address)
	defer src.Close()
	dst, err := net.Dial("tcp", address)
	if err != nil {
		log.Println("Dial Error:" + err.Error())
		return
	}
	defer dst.Close()

	done := make(chan struct{})

	go func() {
		io.Copy(dst, src)
		done <- struct{}{}
		log.Println("dst -> src close. " + srcAddr)
	}()

	go func() {
		io.Copy(src, dst)
		done <- struct{}{}
		log.Println("src -> dst close. " + srcAddr)
	}()

	<-done
	log.Println("connection closed. " + srcAddr)
}

func proxy(src, dst string) {
	listener, err := net.Listen("tcp", src)
	if err != nil {
		log.Fatalln(err.Error())
	}
	log.Printf("start proxy:%s -> %s\n", src, dst)
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("Accept Error:", err)
			continue
		}
		go copyConn(conn, dst)
	}
}

func main() {
	if len(os.Args) < 2 {
		log.Fatalln("invalid argument")
	}
	confFile := os.Args[1]
	file, err := os.Open(confFile)
	if err != nil {
		log.Fatalln(err.Error())
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.Trim(scanner.Text(), " ")
		if len(line) == 0 {
			continue
		}
		addres := strings.Split(line, " ")
		if len(addres) < 2 {
			log.Fatalf("parse fail:%s\n", line)
		}
		go proxy(addres[0], addres[1])
	}
	c := make(chan struct{})
	<-c
}
