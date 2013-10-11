package snmp

import (
    "fmt"
    "strings"
    "strconv"
    "encoding/hex"
    "errors"
)

type Data struct {
    datatype byte
    datalen  int
    data     []byte
}

type Query struct {
    Version    int
    Community  string
    RequestId  uint32
    OIDs       map[string]string
}

// Accepts community string and OID and returns an SNMP request
func Get(data Query) ([]byte, error) {
    var oid_binding []byte

    // encode the OIDs
    for oid, value := range data.OIDs {
        oid_string  := Encode(0x6, EncodeOID(oid))
        oid_data    := value
        oid_binding  = append(oid_binding, Encode(0x30, append(oid_string, oid_data...))...)
    }

    // group together all of the OID->value pairs.
    oid_bindings := Encode(0x30, oid_binding)

    // unique request ID
    tmp_bytes, err := hex.DecodeString(fmt.Sprintf("%x", data.RequestId))
    if err != nil {
        return nil, err
    }
    request_id   := Encode(0x2, tmp_bytes[0:])

    // error status (should be 0)
    error_status := Encode(0x2, []byte("\x00"))
    // error index (should be 0)
    error_index  := Encode(0x2, []byte("\x00"))

    // concatenate request_id + error_status + error_index + oid_bindings
    tmp := append(request_id, error_status...)
    tmp  = append(tmp, error_index...)
    tmp  = append(tmp, oid_bindings...)

    // create SNMP payload
    snmp_data := Encode(0xa1, tmp)

    // SNMP header
    // SNMP version (0x0 = v1, 0x1 = v2c)
    tmp_bytes, err = hex.DecodeString(fmt.Sprintf("%.2x", data.Version))
    if err != nil {
        return nil, err
    }
    snmp_version      := Encode(0x2, tmp_bytes[0:])
    community_string  := Encode(0x4, []byte(data.Community))

    tmp = append(snmp_version, community_string...)
    tmp  = append(tmp, snmp_data...)

    // encode SNMP packet
    return Encode(0x30, tmp), nil
}

// Decode SNMP response
func GetResponse(data []byte) (Query, error) {
    var response Query

    // extract snmp header
    snmp_header := Decode(data)
    if snmp_header.datatype != 0x30 {
        return response, errors.New("SNMP header has invalid data type (should be 0x30)")
    } else if snmp_header.datalen > len(data) - 2 {
        return response, errors.New("SNMP header has invalid data length")
    }

    index := 2

    // get snmp version
    snmp_version := Decode(data[index:])
    if snmp_version.datatype != 0x2 {
        return response, errors.New("SNMP version has invalid data type (should be 0x02)")
    } else if snmp_version.datalen != 1 {
        return response, errors.New("SNMP version has invalid data length")
    }

    index += 2 + snmp_version.datalen

    // get snmp community string
    community_string := Decode(data[index:])
    if community_string.datatype != 0x4 {
        return response, errors.New("SNMP community string has invalid data type (should be 0x04)")
    } else if community_string.datalen > len(data) - index - 2 {
        return response, errors.New("SNMP community string has invalid data length")
    }

    index += 2 + community_string.datalen

    // get the main payload
    snmp_payload := Decode(data[index:]).data

    // extract request id
    request_id := Decode(snmp_payload)
    if request_id.datatype != 0x2 {
        return response, errors.New("SNMP request ID has invalid data type (should be 0x02)")
    } else if request_id.datalen != 4 {
        return response, errors.New("SNMP request ID has invalid data length")
    }

    index  = 2 + request_id.datalen

    // extract error status
    error_status := Decode(snmp_payload[index:])
    if error_status.datatype != 0x2 {
        return response, errors.New("SNMP error status has invalid data type (should be 0x02)")
    } else if error_status.datalen != 1 {
        return response, errors.New("SNMP error status has invalid data length")
    }

    index += 2 + error_status.datalen

    // extract error index
    error_index := Decode(snmp_payload[index:])
    if error_index.datatype != 0x2 {
        return response, errors.New("SNMP error index has invalid data type (should be 0x02)")
    } else if error_index.datalen != 1 {
        return response, errors.New("SNMP error index has invalid data length")
    }

    index += 2 + error_index.datalen

    // parse out data into SNMPResponse
    response.Version     = int(snmp_version.data[0])
    response.Community   = string(community_string.data)

    request_id_int, err := strconv.ParseInt(hex.EncodeToString(request_id.data), 16, 0)
    if err != nil {
        return response, err
    }

    response.RequestId  = uint32(request_id_int)
    response.OIDs       = make(map[string]string)

    oid_binds := Decode(snmp_payload[index:])
    for index = 0 ; index < oid_binds.datalen ; {
        oid_binding := Decode(oid_binds.data[index:])
        if oid_binding.datatype != 0x30 {
            return response, errors.New("SNMP OID binding has invalid data type (should be 0x30)")
        } else if oid_binding.datalen > len(oid_binds.data[index:]) - 2 {
            return response, errors.New("SNMP OID binding has invalid data length")
        }

        oid_data := Decode(oid_binding.data)
        if oid_data.datatype != 0x6 {
            return response, errors.New("SNMP OID has invalid data type (should be 0x5)")
        } else if oid_data.datalen > len(oid_binding.data) - 2 {
            return response, errors.New("SNMP OID has invalid data length")
        }

        oid_value := Decode(oid_binding.data[2 + oid_data.datalen:])
        if oid_value.datalen > len(oid_binding.data) - oid_data.datalen - 4 {
            return response, errors.New("SNMP OID value has invalid data length")
        }

        response.OIDs[DecodeOID(oid_data.data)] = string(oid_value.data)
        index += 2 + oid_binding.datalen
    }

    return response, nil
}

// Encodes SNMP data:
//   Valid data types:
//     * 0x2  = integer
//     * 0x4  = string
//     * 0x5  = null
//     * 0x6  = OID
//     * 0x30 = array / section header / grouping
//     * 0xa1 = get-next-request
//     * 0xa2 = get-response
func Encode(datatype byte, data []byte) []byte {
    var snmp_encode []byte
    snmp_encode = append(snmp_encode, datatype, byte(len(data)))
    return append(snmp_encode, data...)
}

// Decode SNMP responses
func Decode(data []byte) Data {
    datatype := data[0]
    datalen  := int(data[1])

    if datalen > len(data) - 2 {
        datalen = len(data) - 2
    }

    return Data { datatype, datalen, data[2:2+datalen] }
}

// Encode OID string
func EncodeOID(oid string) []byte {
    split_oid    := strings.Split(oid, ".")
    final_oid    := make([]byte, len(split_oid) - 1)
    final_oid[0] = 0x2b

    for index := 2 ; index < len(split_oid) ; index++ {
        val, _ := strconv.Atoi(split_oid[index])
        final_oid[index-1] = byte(val)
    }

    return final_oid
}

// Convert OID to string version
func DecodeOID(oid []byte) string {
    final_oid := "1.3"
    for index := 1 ; index < len(oid) ; index++ {
        final_oid = fmt.Sprintf("%s.%d", final_oid, oid[index])
    }
    return final_oid
}

