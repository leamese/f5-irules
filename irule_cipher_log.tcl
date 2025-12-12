#
# TLS Cipher Logging iRule
# ------------------------
# Logs client-side and server-side TLS cipher details to a SIEM using HSL.
# Includes SNI when available, otherwise defaults to "UNKNOWN".
#
# Requirements:
#  - Log publisher: /Common/log_publisher_xxx
#  - Virtual server must use ClientSSL and/or ServerSSL profiles
#
# Purpose:
#  Helps analyze real-world cipher usage, validate TLS strategy,
#  and identify legacy or weak ciphers in production traffic.
#

when CLIENTSSL_HANDSHAKE {
    set timestamp [clock format [clock seconds] -format {%b %e %H:%M:%S}]
    set hsl [HSL::open -publisher /Common/log_publisher_xxx]
    # set sni_name "UNKNOWN"  ; # Default value if SNI is missing

    set sni_name "UNKNOWN"

    if { [SSL::extensions exists -type 0] } {
        set raw_sni [SSL::extensions -type 0]
        if { [string length $raw_sni] >= 5 } {
            # Use binary scan safely: skip first 9 bytes, then read the rest
            if { [catch { binary scan $raw_sni {@9A*} sni_name } ] } {
                set sni_name "UNKNOWN"
            }
        }
    }

        set log "tcpip.client.ip=[IP::client_addr]|\
tls.cipher.version=[SSL::cipher version]|\
tls.cipher.name=[SSL::cipher name]|\
tls.cipher.bits=[SSL::cipher bits]|\
vip=[virtual name]|\
ssl.sni=$sni_name"

        HSL::send $hsl "<134>$timestamp $static::tcl_platform(machine) info cipherlog: clientssl| $log"
    
}

when SERVERSSL_HANDSHAKE {
    set timestamp2 [clock format [clock seconds] -format {%b %e %H:%M:%S}]

        set log "tcpip.client.ip=[IP::client_addr]|\
tcpip.server.ip=[IP::remote_addr]|\
tls.cipher.version=[SSL::cipher version]|\
tls.cipher.name=[SSL::cipher name]|\
tls.cipher.bits=[SSL::cipher bits]|\
vip=[virtual name]|\
ssl.sni=$sni_name"

        HSL::send $hsl "<134>$timestamp2 $static::tcl_platform(machine) info cipherlog: serverssl| $log"
    
}
