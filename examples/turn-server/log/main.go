// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package main implements a TURN server with logging.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"syscall"
	"github.com/pion/logging"
	"github.com/pion/stun/v2"
	"github.com/pion/turn/v3"
)

// stunLogger wraps a PacketConn and prints incoming/outgoing STUN packets
// This pattern could be used to capture/inspect/modify data as well
type stunLogger struct {
	net.PacketConn
}

func (s *stunLogger) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if n, err = s.PacketConn.WriteTo(p, addr); err == nil && stun.IsMessage(p) {
		msg := &stun.Message{Raw: p}
		if err = msg.Decode(); err != nil {
			return
		}

		fmt.Printf("Outbound STUN: %s \n", msg.String())
	}

	return
}

func (s *stunLogger) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	if n, addr, err = s.PacketConn.ReadFrom(p); err == nil && stun.IsMessage(p) {
		msg := &stun.Message{Raw: p}
		if err = msg.Decode(); err != nil {
			return
		}

		fmt.Printf("Inbound STUN: %s \n", msg.String())
	}

	return
}

func main() {
	publicIP := flag.String("public-ip", "", "IP Address that TURN can be contacted by.")
	users := flag.String("users", "", "List of username and password (e.g. \"user=pass,user=pass\")")
	authSecret := flag.String("authSecret", "", "Shared secret for the Long Term Credential Mechanism")
	realm := flag.String("realm", "pion.ly", "Realm (defaults to \"pion.ly\")")
	
	port := flag.Int("port", 3478, "Listening port.")	
	minPort := flag.Int("min_port", 50000, "Minimuim UDP Port")
	maxPort := flag.Int("max_port", 55000, "Maximuim UDP Port")	
	flag.Parse()
	
	if *minPort <= 0 || *maxPort <= 0 || *minPort > *maxPort {
		log.Fatalf("UDP range: bad range")
	}	

	if len(*publicIP) == 0 {
		log.Fatalf("'public-ip' is required")
	} else if len(*users) == 0 && len(*authSecret) == 0 {
		log.Fatalf("'users' or 'authSecret' is required")
	}	

	// Create a UDP listener to pass into pion/turn
	// pion/turn itself doesn't allocate any UDP sockets, but lets the user pass them in
	// this allows us to add logging, storage or modify inbound/outbound traffic
	udpListener, err := net.ListenPacket("udp4", "0.0.0.0:"+strconv.Itoa(*port))
	if err != nil {
		log.Panicf("Failed to create TURN server listener: %s", err)
	}

	// Cache -users flag for easy lookup later
	// If passwords are stored they should be saved to your DB hashed using turn.GenerateAuthKey
	
	usersMap := map[string][]byte{}
	
	for _, kv := range regexp.MustCompile(`(\w+)=(\w+)`).FindAllStringSubmatch(*users, -1) {
		usersMap[kv[1]] = turn.GenerateAuthKey(kv[1], *realm, kv[2])
	}
	
	if len(*authSecret) > 0 {	
		logger := logging.NewDefaultLeveledLoggerForScope("lt-creds", logging.LogLevelTrace, os.Stdout)
	
		s, err := turn.NewServer(turn.ServerConfig{
			Realm: *realm,		
			AuthHandler: turn.LongTermTURNRESTAuthHandler(*authSecret, logger),
			PacketConnConfigs: []turn.PacketConnConfig{
				{
					PacketConn: &stunLogger{udpListener},
					RelayAddressGenerator: &turn.RelayAddressGeneratorPortRange{
						RelayAddress: net.ParseIP(*publicIP), // Claim that we are listening on IP passed by user (This should be your Public IP)
						Address:      "0.0.0.0",              // But actually be listening on every interface
						MinPort:      uint16(*minPort),
						MaxPort:      uint16(*maxPort),
					},					
				},
			},
		})
		
		if err != nil {
			log.Panic(err)
		}

		// Block until user sends SIGINT or SIGTERM
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
		<-sigs

		if err = s.Close(); err != nil {
			log.Panic(err)
		}	
		
	} else {
		
		s, err := turn.NewServer(turn.ServerConfig{
			Realm: *realm,		
			AuthHandler: func(username string, realm string, srcAddr net.Addr) ([]byte, bool) {
				if key, ok := usersMap[username]; ok {
					return key, true
				}
				return nil, false
			},
			PacketConnConfigs: []turn.PacketConnConfig{
				{
					PacketConn: &stunLogger{udpListener},
					RelayAddressGenerator: &turn.RelayAddressGeneratorPortRange{
						RelayAddress: net.ParseIP(*publicIP), // Claim that we are listening on IP passed by user (This should be your Public IP)
						Address:      "0.0.0.0",              // But actually be listening on every interface
						MinPort:      uint16(*minPort),
						MaxPort:      uint16(*maxPort),
					},					
				},
			},
		})
		
		if err != nil {
			log.Panic(err)
		}

		// Block until user sends SIGINT or SIGTERM
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
		<-sigs

		if err = s.Close(); err != nil {
			log.Panic(err)
		}		
	}
}
