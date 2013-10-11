package main

import (
    "net/ipaddr"
    "os"
    "log"
    "fmt"
)

func main() {
    if len(os.Args) != 2 {
        fmt.Printf("Usage: %s <ip network>\n", os.Args[0])
        return
    }

    ip_queue, err := ipaddr.IPv4NetworkQueue(os.Args[1])
    if err != nil {
        log.Fatal(err)
    }

    for addr := range ip_queue {
        fmt.Printf(" - %s\n", addr)
    }

    return
}
