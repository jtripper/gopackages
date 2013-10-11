package main

import (
    "net/snmp"
    "net"
    "log"
    "fmt"
    "os"
    "math/rand"
    "time"
)

func main() {
    rand.Seed(time.Now().UTC().UnixNano())

    if len(os.Args) != 2 {
        fmt.Printf("Usage: %s <host>\n", os.Args[0])
        return
    }

    // Validate and create host string
    host := os.Args[1]
    _, _, err := net.SplitHostPort(host)
    if err != nil {
        if net.ParseIP(host) == nil {
            fmt.Printf("Not a valid IP!\n")
            return
        }
        host = net.JoinHostPort(host, "161")
    }

    data, err := do_snmp("public", host)
    if err != nil {
        log.Fatal(err)
    }

    // Display results
    fmt.Printf(" - Community string, %s (request id: 0x%x)\n", data.Community, data.RequestId)
    for oid, value := range data.OIDs {
        fmt.Printf(" - %s: %s\n", oid, value)
    }
}

// Basic SNMP client
func do_snmp(community string, host string) (snmp.Query, error) {
    // fill in snmp.Query struct
    var data snmp.Query
    data.Version   = 0x1       // v1 = 0x0, v2c = 0x1
    data.Community = community // community string
    data.RequestId = rand.Uint32() // random request id

    // fill in the OID map
    data.OIDs = make(map[string]string)
    data.OIDs["1.3.6.1.2.1"] = string(snmp.Encode(0x5, []byte("")))

    // open connection
    conn, err := net.Dial("udp", host)
    if err != nil {
        return data, err
    }

    // craft snmp packet
    snmpdata, err := snmp.Get(data)
    if err != nil {
        return data, err
    }

    // send the packet
    _, err = conn.Write(snmpdata)
    if err != nil {
        return data, err
    }

    // read the reply
    var buf [65535]byte
    _, err = conn.Read(buf[0:])
    if err != nil {
        return data, err
    }

    // parse the reply
    data, err = snmp.GetResponse(buf[0:])
    if err != nil {
        return data, err
    }

    // return the reply
    return data, nil
}
