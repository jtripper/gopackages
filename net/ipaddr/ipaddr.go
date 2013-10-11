package ipaddr

import (
    "net"
    "strings"
    "strconv"
    "fmt"
    "errors"
)

// IPv4Network type, contains the highest address, CIDR value, highest network address, and the lowest network address.
type IPv4Network struct {
    mask uint64
    cidr uint64
    max  uint64
    addr uint64
}

// Convert IPv4 string representation to integer representation.
func InetAton(ip_addr string) (uint64, error) {
    var final_addr uint64

    addr := net.ParseIP(ip_addr)
    if addr == nil {
        return 0, errors.New("Invalid IP address.")
    }

    for _, b := range addr[12:] {
        final_addr += uint64(b)
        final_addr = final_addr << 8
    }

    final_addr = final_addr >> 8
    return final_addr, nil
}

// Convert IPv4 integer to IP string.
func InetNtoa(addr uint64) string {
    bits := make([]uint64, 4)

    for i := 0 ; i < 4 ; i++ {
        bits[i] = uint64(0xff) & addr
        addr = addr >> 8
    }

    return fmt.Sprintf("%d.%d.%d.%d", bits[3], bits[2], bits[1], bits[0])
}

// Start a queue of IP's in an IPv4 network
func IPv4NetworkQueue(ip_range string) (<-chan string, error) {
    ip_channel   := make(chan string)

    network, err := InitIPv4Network(ip_range)
    if err != nil {
        return nil, err
    }

    go gen_ips(network, ip_channel)
    return ip_channel, nil
}

func gen_ips(network *IPv4Network, ip_channel chan string) {
    for addr := range network.Iterate() {
        ip_channel <- addr
    }
    close(ip_channel)
}

// Initialize an IPv4Network on a given CIDR address.
func InitIPv4Network(ip_range string) (*IPv4Network, error) {
    network := new(IPv4Network)

    if err := network.parse_range(ip_range) ; err != nil {
        return nil, err
    }

    num_addrs    := uint64(0xffffffff) >> network.cidr
    network.mask  = ^num_addrs
    network.addr &= network.mask
    network.max   = network.addr + num_addrs

    return network, nil
}

// Iterate over all IPv4 adresses.
func (i *IPv4Network)Iterate() <-chan string {
    addr_chan := make(chan string)
    go i.iterate_ipv4(addr_chan)
    return addr_chan
}

// Internal iterator.
func (i *IPv4Network)iterate_ipv4(addr_chan chan string) {
    for addr := i.addr ; addr <= i.max ; addr++ {
        addr_chan <- InetNtoa(addr)
    }
    close(addr_chan)
}

// Parse out address and CIDR value from an address string.
func (i *IPv4Network)parse_range(ip_range string) error {
    s := strings.Split(ip_range, "/")
    if len(s) != 2 {
        return errors.New("Invalid CIDR address.")
    }

    cidr, err := strconv.Atoi(s[1])
    if err != nil {
        return err
    }

    if cidr > 32 {
        return errors.New("Invalid CIDR address.")
    }

    i.cidr = uint64(cidr)

    if i.addr, err = InetAton(s[0]) ; err != nil {
        return err
    }

    return nil
}
