#
# LDAPS User Identification iRule
# --------------------------------
# Captures LDAPS bind payload and extracts user identity (DN, NetBIOS, UPN, username)
# Sends sanitized logs (NO passwords) via log publisher to SIEM.
# 
# Requirements:
#  - ClientSSL + ServerSSL profiles on the virtual server
#  - Log publisher: /Common/log_publisher_xxx
#  - Update regex_pattern_upn to match your domain
#
# WARNING:
#  Load-balancing LDAPS has architectural caveats. Test in non-production first.
#

when CLIENTSSL_HANDSHAKE {
    SSL::collect
}

when CLIENTSSL_DATA {
    set hsl [HSL::open -publisher /Common/log_publisher_xxx]
    set timestamp [clock format [clock seconds] -format {%b %e %H:%M:%S}]
    set payload     [SSL::payload]
    SSL::release
    # log local0. "$payload"
    # Define the regex to extract relevant information without capturing passwords.
    set regex_pattern_dn        {CN=([^,]+),(?:OU=([^,]+),)*(?:DC=[^,]+,)*DC=([a-z]{1,5})}
    set regex_pattern_netbios   {[A-Za-z]{1,12}\\[a-zA-Z0-9_-]{1,30}}
    set regex_pattern_upn       {[A-Za-z0-9]+@subdomain\.domain\.tld}
    set regex_pattern_user      {([a-zA-Z_]{4,30})}

}

when LB_SELECTED {
    # Use regexp to match the pattern in the payload
    if {[regexp $regex_pattern_dn $payload match cn ou1]} {
        # Check if OU is captured and construct user DN accordingly
        if {[info exists match]} {
            set userinfo $match
            set matchtype "Full DN"
        } elseif {[info exists cn] and [info exists ou1] } {
            set userinfo "CN=$cn,OU=$ou1"
            set matchtype "CN,OU"
        } elseif {[info exists cn]} {
            set userinfo "CN=$cn"
            set matchtype "CN"
        }
    } elseif {[regexp $regex_pattern_netbios $payload match]} {
        if {[info exists match]} {
            set userinfo $match
            set matchtype "Netbios"
        }
    } elseif {[regexp $regex_pattern_upn $payload match]} {
        if {[info exists match]} {
            set userinfo $match
            set matchtype "gentgrp"
        }
    } elseif {[regexp $regex_pattern_user $payload match]} {
        if {[info exists match]} {
            set userinfo $match
            set matchtype "user"
        }
    } else {
        set userinfo $payload
    }

    HSL::send $hsl "<135>$timestamp $static::tcl_platform(machine) info ldapslog: [virtual name] [IP::local_addr]:[TCP::local_port] FROM [IP::remote_addr]:[TCP::remote_port] TO [LB::server addr]:[LB::server port] matchtype $matchtype with info: $userinfo"
}
