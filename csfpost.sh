#!/bin/sh
# =============================================================================
# Script: Docker Traffic Control with CSF (ConfigServer Security & Firewall)
# Purpose: This script integrates Docker container traffic control with CSF,
#          restricting container access based on CSF's rules unless explicitly
#          allowed. You might want to bypass CSF for certain containers
#          (like nginx) to get the client's real IP.
# Maintainer:  Scott Mcintyre <me@scott.cm>
# Based on: https://github.com/juli3nk/csf-post-docker

# License: MIT License (see below)
#
# =============================================================================
# License:
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# =============================================================================

# ============ USER CONFIGURABLE VARIABLES ============ #
# ALLOWED_DNAT_PORTS: List of container ports to allow DNAT (bypass CSF),
# such as 80 or 443 for nginx. If set to "all", DNAT is allowed for all ports
# exposed by the container. If empty, no ports are DNATed and CSF handles all.
# Examples:
# ALLOWED_DNAT_PORTS="80 443" # Allow DNAT for ports 80 and 443
# ALLOWED_DNAT_PORTS="all" # Allow all ports exposed by containers
ALLOWED_DNAT_PORTS=""

# ALLOWED_DNAT_SOURCE: Restrict the source IP for DNAT.
# Examples:
# ALLOWED_DNAT_SOURCE="10.1.0.0/24" # Only allow DNAT from internal VPN
ALLOWED_DNAT_SOURCE="0.0.0.0/0"

# DOCKER_INT: Docker network interface.
DOCKER_INT="docker0"

# DOCKER_NETWORK: Docker network range.
DOCKER_NETWORK="172.17.0.0/16"
# ===================================================== #

export PATH="$PATH:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

chain_exists() {
    [ $# -lt 1 -o $# -gt 2 ] && {
        echo "Usage: chain_exists <chain_name> [table]" >&2
        return 1
    }
    local chain_name="$1"
    shift
    [ $# -eq 1 ] && local table="--table $1"
    iptables $table -n --list "$chain_name" >/dev/null 2>&1
}

add_to_forward() {
    local docker_int=$1

    if [ $(iptables -nvL FORWARD | grep ${docker_int} | wc -l) -eq 0 ]; then
        iptables -A FORWARD -o ${docker_int} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
        iptables -A FORWARD -o ${docker_int} -j DOCKER
        iptables -A FORWARD -i ${docker_int} ! -o ${docker_int} -j ACCEPT
        iptables -A FORWARD -i ${docker_int} -o ${docker_int} -j ACCEPT
    fi
}

add_to_nat() {
    local docker_int=$1
    local subnet=$2

    iptables -t nat -A POSTROUTING -s ${subnet} ! -o ${docker_int} -j MASQUERADE
    iptables -t nat -A DOCKER -i ${docker_int} -j RETURN
}

add_to_docker_isolation() {
    local docker_int=$1

    iptables -A DOCKER-ISOLATION-STAGE-1 -i ${docker_int} ! -o ${docker_int} -j DOCKER-ISOLATION-STAGE-2
    iptables -A DOCKER-ISOLATION-STAGE-2 -o ${docker_int} -j DROP
}

iptables-save | grep -v -- '-j DOCKER' | iptables-restore
chain_exists DOCKER && iptables -X DOCKER
chain_exists DOCKER nat && iptables -t nat -X DOCKER

iptables -N DOCKER
iptables -N DOCKER-ISOLATION-STAGE-1
iptables -N DOCKER-ISOLATION-STAGE-2
iptables -N DOCKER-USER

iptables -t nat -N DOCKER

iptables -A FORWARD -j DOCKER-USER
iptables -A FORWARD -j DOCKER-ISOLATION-STAGE-1
add_to_forward ${DOCKER_INT}

iptables -t nat -A PREROUTING -m addrtype --dst-type LOCAL -j DOCKER
iptables -t nat -A OUTPUT ! -d 127.0.0.0/8 -m addrtype --dst-type LOCAL -j DOCKER
iptables -t nat -A POSTROUTING -s ${DOCKER_NETWORK} ! -o ${DOCKER_INT} -j MASQUERADE

bridges=$(docker network ls -q --filter='Driver=bridge')

for bridge in $bridges; do
    DOCKER_NET_INT=$(docker network inspect -f '{{"'br-$bridge'" | or (index .Options "com.docker.network.bridge.name")}}' $bridge)
    subnet=$(docker network inspect -f '{{(index .IPAM.Config 0).Subnet}}' $bridge)

    add_to_nat ${DOCKER_NET_INT} ${subnet}
    add_to_forward ${DOCKER_NET_INT}
    add_to_docker_isolation ${DOCKER_NET_INT}
done

containers=$(docker ps -q)
if [ $(echo ${containers} | wc -c) -gt "1" ]; then
    for container in ${containers}; do
        # Dynamically fetch the first network name
        network_name=$(docker inspect -f '{{range $key, $value := .NetworkSettings.Networks}}{{$key}}{{end}}' ${container})

        if [ "${network_name}" == "bridge" ]; then
            # Default bridge network
            DOCKER_NET_INT=${DOCKER_INT}
            ipaddr=$(docker inspect -f "{{.NetworkSettings.IPAddress}}" ${container})
        else
            # Custom network, fetch details dynamically
            bridge=$(docker inspect -f "{{with index .NetworkSettings.Networks \"${network_name}\"}}{{.NetworkID}}{{end}}" ${container} | cut -c -12)

            # Fallback to manually prepending "br-" if bridge name is not found in Options
            DOCKER_NET_INT=$(docker network inspect -f '{{index .Options "com.docker.network.bridge.name"}}' ${bridge})
            if [ -z "$DOCKER_NET_INT" ]; then
                DOCKER_NET_INT="br-${bridge}"
            fi

            ipaddr=$(docker inspect -f "{{with index .NetworkSettings.Networks \"${network_name}\"}}{{.IPAddress}}{{end}}" ${container})
        fi

        rules=$(docker port ${container} | sed 's/ //g')

        if [ $(echo ${rules} | wc -c) -gt "1" ]; then
            for rule in ${rules}; do
                src=$(echo ${rule} | awk -F'->' '{ print $2 }')
                dst=$(echo ${rule} | awk -F'->' '{ print $1 }')

                # Check if it's IPv6 and skip processing if true
                # Currently don't support ipv6
                case "$src" in
                *::*)
                    echo "Skipping IPv6 rule: $rule"
                    continue
                    ;;
                esac
                src_ip=$(echo ${src} | awk -F':' '{ print $1 }')
                src_port=$(echo ${src} | awk -F':' '{ print $2 }')

                dst_port=$(echo ${dst} | awk -F'/' '{ print $1 }')
                dst_proto=$(echo ${dst} | awk -F'/' '{ print $2 }')

                iptables -A DOCKER -d ${ipaddr}/32 ! -i ${DOCKER_NET_INT} -o ${DOCKER_NET_INT} -p ${dst_proto} -m ${dst_proto} --dport ${dst_port} -j ACCEPT

                iptables -t nat -A POSTROUTING -s ${ipaddr}/32 -d ${ipaddr}/32 -p ${dst_proto} -m ${dst_proto} --dport ${dst_port} -j MASQUERADE

                iptables_opt_src=""
                if [ "$src_ip" != "0.0.0.0" ]; then
                    iptables_opt_src="-d ${src_ip}/32 "
                fi
                # We want to only allow access to ports configured in CSF
                # So do not DNAT by default and only DNAT ports defined above
                # As these bypass CSF rules
                if [ -n "$src_ip" ]; then
                    if [ -n "$ALLOWED_DNAT_PORTS" ]; then
                        # If all is configured, then apply DNAT rule
                        if [ "$ALLOWED_DNAT_PORTS" = "all" ]; then
                            iptables -t nat -A DOCKER -s "$ALLOWED_DNAT_SOURCE" ${iptables_opt_src} ! -i ${DOCKER_NET_INT} -p ${dst_proto} -m ${dst_proto} --dport ${src_port} -j DNAT --to-destination ${ipaddr}:${dst_port}
                        else
                            # Iterate over ALLOWED_DNAT_PORTS to see if $src_port is allowed
                            for allowed_port in $ALLOWED_DNAT_PORTS; do
                                if [ "$allowed_port" = "$src_port" ]; then
                                    iptables -t nat -A DOCKER -s "$ALLOWED_DNAT_SOURCE" ${iptables_opt_src} ! -i ${DOCKER_NET_INT} -p ${dst_proto} -m ${dst_proto} --dport ${src_port} -j DNAT --to-destination ${ipaddr}:${dst_port}
                                fi
                            done
                        fi
                    fi
                fi
            done
        fi
    done
fi

# Expose established connections to the containers
iptables -t filter -A FORWARD -o docker0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

iptables -A DOCKER-ISOLATION-STAGE-1 -j RETURN
iptables -A DOCKER-ISOLATION-STAGE-2 -j RETURN
iptables -A DOCKER-USER -j RETURN

if [ $(iptables -t nat -nvL DOCKER | grep ${DOCKER_INT} | wc -l) -eq 0 ]; then
    iptables -t nat -I DOCKER -i ${DOCKER_INT} -j RETURN
fi
