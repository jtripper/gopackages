/*
 * net/ipaddr example
 * (C) 2013 jtRIPper
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 1, or (at your option)
 * any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

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
