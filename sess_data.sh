#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# L2TP tunnels between 2 hosts
#
#             host-1         | router | host-2
#                            |        |
#             lo       l2tp  |        |  l2tp       lo
#   172.16.101.1 172.16.1.1  |        |  172.16.1.2 172.16.101.2
#    fc00:101::1  fc00:1::1  |        |  fc00:1::2  fc00:101::2
#                            |        |
#                       eth0 |        | eth0
#                   10.1.1.1 |        | 10.1.2.1
#              2001:db8:1::1 |        | 2001:db8:2::1

VERBOSE=0
PAUSE_ON_FAIL=no

which ping6 > /dev/null 2>&1 && ping6=$(which ping6) || ping6=$(which ping)

################################################################################
#
log_test()
{
    local rc=$1
    local expected=$2
    local msg="$3"

    if [ ${rc} -eq ${expected} ]; then
        printf "TEST: %-60s  [ OK ]\n" "${msg}"
        nsuccess=$((nsuccess+1))
    else
        ret=1
        nfail=$((nfail+1))
        printf "TEST: %-60s  [FAIL]\n" "${msg}"
        if [ "${PAUSE_ON_FAIL}" = "yes" ]; then
            echo
            echo "hit enter to continue, 'q' to quit"
            read a
            [ "$a" = "q" ] && exit 1
        fi
    fi
}

run_cmd()
{
    local ns
    local cmd
    local out
    local rc

    ns="$1"
    shift
    cmd="$*"

    if [ "$VERBOSE" = "1" ]; then
        printf "    COMMAND: $cmd\n"
    fi

    out=$(eval ip netns exec ${ns} ${cmd} 2>&1)
    rc=$?
    if [ "$VERBOSE" = "1" -a -n "$out" ]; then
        echo "    $out"
    fi

    [ "$VERBOSE" = "1" ] && echo

    return $rc
}

################################################################################
# create namespaces and interconnects

create_ns()
{
    local ns=$1
    local addr=$2
    local addr6=$3

    [ -z "${addr}" ] && addr="-"
    [ -z "${addr6}" ] && addr6="-"

    ip netns add ${ns}

    ip -netns ${ns} link set lo up
    if [ "${addr}" != "-" ]; then
        ip -netns ${ns} addr add dev lo ${addr}
    fi
    if [ "${addr6}" != "-" ]; then
        ip -netns ${ns} -6 addr add dev lo ${addr6}
    fi

    ip -netns ${ns} ro add unreachable default metric 8192
    ip -netns ${ns} -6 ro add unreachable default metric 8192

    ip netns exec ${ns} sysctl -qw net.ipv4.ip_forward=1
    ip netns exec ${ns} sysctl -qw net.ipv6.conf.all.keep_addr_on_down=1
    ip netns exec ${ns} sysctl -qw net.ipv6.conf.all.forwarding=1
    ip netns exec ${ns} sysctl -qw net.ipv6.conf.default.forwarding=1
    ip netns exec ${ns} sysctl -qw net.ipv6.conf.default.accept_dad=0
}

# create veth pair to connect namespaces and apply addresses.
connect_ns()
{
    local ns1=$1
    local ns1_dev=$2
    local ns1_addr=$3
    local ns1_addr6=$4
    local ns2=$5
    local ns2_dev=$6
    local ns2_addr=$7
    local ns2_addr6=$8

    ip -netns ${ns1} li add ${ns1_dev} type veth peer name tmp
    ip -netns ${ns1} li set ${ns1_dev} up
    ip -netns ${ns1} li set tmp netns ${ns2} name ${ns2_dev}
    ip -netns ${ns2} li set ${ns2_dev} up

    if [ "${ns1_addr}" != "-" ]; then
        ip -netns ${ns1} addr add dev ${ns1_dev} ${ns1_addr}
        ip -netns ${ns2} addr add dev ${ns2_dev} ${ns2_addr}
    fi

    if [ "${ns1_addr6}" != "-" ]; then
        ip -netns ${ns1} addr add dev ${ns1_dev} ${ns1_addr6}
        ip -netns ${ns2} addr add dev ${ns2_dev} ${ns2_addr6}
    fi
}

# wait for file to exist
wait_file()
{
    local filename=$1
    local interval=$2
    local max_polls=$3

    for n in $(seq 1 $max_polls)
    do
        test -f $filename && return
        sleep $interval
    done
    echo "timeout waiting for file $filename"
    false
}

# wait for file to contain a string
wait_file_contains()
{
    local filename=$1
    local interval=$2
    local max_polls=$3
    local match=$4

    for n in $(seq 1 $max_polls)
    do
        test -f $filename && grep -q $match $filename && return
        sleep $interval
    done
    echo "timeout waiting for file $filename to contain \'$match\'"
    false
}

################################################################################
# test setup

cleanup()
{
    local ns
    local j=$(jobs -p)

    test -z "$j" || kill $j > /dev/null 2>&1 && wait $j >/dev/null 2>&1
    rm -f /tmp/l2tp-ktest-sess-dataif-[cs]*
    for ns in host-1 host-2 router
    do
        ip netns del ${ns} 2>/dev/null
    done
}

setup_l2tp_session()
{
    local ip_version=$1
    local l2tp_version=$2
    local encap=$3
    local pwtype="$4"
    local cookie_len=$5
    local timeout=$6
    local bad_cookie="$7"
    local cookie4_1="01234567"
    local cookie4_2="89abcdef"
    local cookie8_1="0123456789abcdef"
    local cookie8_2="fedcba9876543210"
    local cookie_arg=""
    local ifname=""
    local timeout_arg=""
    local port_1=20000
    local port_2=10000
    local host_ip_1="10.1.1.1"
    local host_ip_2="10.1.2.1"
    local l2tp_ip_1="172.16.1.1"
    local l2tp_ip_2="172.16.1.2"
    local family_arg=""

    if test $ip_version -eq 6; then
        family_arg="-f inet6"
        host_ip_1="2001:db8:1::1"
        host_ip_2="2001:db8:2::1"
        l2tp_ip_1="fc00:1::1"
        l2tp_ip_2="fc00:1::2"
    fi

    test "$pwtype" = "ppp" && ifname="ppp0" || ifname="l2tpeth0"

    test $timeout -eq 0 || timeout_arg="-T $timeout"

    #
    # configure l2tp tunnel server on host-1
    #
    test $cookie_len -eq 4 && cookie_arg="-k $cookie4_1 -K $cookie4_2"
    test $cookie_len -eq 8 && cookie_arg="-k $cookie8_1 -K $cookie8_2"
    run_cmd host-1 ./sess_dataif $family_arg -L ${host_ip_1}/${port_1} -P ${host_ip_2}/${port_2} -v $l2tp_version -e $encap -p $pwtype $cookie_arg $timeout_arg &
    wait_file_contains /tmp/l2tp-ktest-sess-dataif-s 0.1 10 $ifname

    ip -netns host-1 link set dev $ifname up
    ip -netns host-1 addr add dev $ifname ${l2tp_ip_1} peer ${l2tp_ip_2}

    # if bad_cookie is set, use it to override cookie_2
    test -z "${bad_cookie}" || cookie4_2=$bad_cookie
    test -z "${bad_cookie}" || cookie8_2=$bad_cookie

    #
    # configure l2tp tunnel client on host-2
    #
    test $cookie_len -eq 0 -a -n "${bad_cookie}" && cookie_arg="-k $cookie4_2"
    test $cookie_len -eq 4 && cookie_arg="-k $cookie4_2 -K $cookie4_1"
    test $cookie_len -eq 8 && cookie_arg="-k $cookie8_2 -K $cookie8_1"
    run_cmd host-2 ./sess_dataif -C $family_arg -L ${host_ip_2}/${port_2} -P ${host_ip_1}/${port_1} -v $l2tp_version -e $encap -p $pwtype $cookie_arg $timeout_arg &
    wait_file_contains /tmp/l2tp-ktest-sess-dataif-c 0.1 10 $ifname

    ip -netns host-2 link set dev $ifname up
    ip -netns host-2 addr add dev $ifname ${l2tp_ip_2} peer ${l2tp_ip_1}

    #
    # add routes to loopback addresses
    #
    if test $ip_version -eq 6; then
        ip -netns host-1 -6 ro add fc00:101::2/128 via ${l2tp_ip_2}
        ip -netns host-2 -6 ro add fc00:101::1/128 via ${l2tp_ip_1}
    else
        ip -netns host-1 ro add 172.16.101.2/32 via ${l2tp_ip_2}
        ip -netns host-2 ro add 172.16.101.1/32 via ${l2tp_ip_1}
    fi
}

setup()
{
    # start clean
    cleanup

    set -e
    create_ns host-1 172.16.101.1/32 fc00:101::1/128
    create_ns host-2 172.16.101.2/32 fc00:101::2/128
    create_ns router

    connect_ns host-1 eth0 10.1.1.1/24 2001:db8:1::1/64 \
           router eth1 10.1.1.2/24 2001:db8:1::2/64

    connect_ns host-2 eth0 10.1.2.1/24 2001:db8:2::1/64 \
           router eth2 10.1.2.2/24 2001:db8:2::2/64

    ip -netns host-1 ro add 10.1.2.0/24 via 10.1.1.2
    ip -netns host-1 -6 ro add 2001:db8:2::/64 via 2001:db8:1::2

    ip -netns host-2 ro add 10.1.1.0/24 via 10.1.2.2
    ip -netns host-2 -6 ro add 2001:db8:1::/64 via 2001:db8:2::2

    set +e
}

################################################################################
# generate traffic through tunnel for various cases

run_ping()
{
    local ip_version=$1
    local pktsize=$2
    local size_arg=""

    test $pktsize -eq 0 || size_arg="-s $pktsize"

    if test $ip_version -eq 4; then
        run_cmd host-1 ping -c1 -w1 ${size_arg} -I 172.16.101.1 172.16.101.2
    else
        run_cmd host-1 ${ping6} -c1 -w1 ${size_arg} -I fc00:101::1 fc00:101::2
    fi
}

test_l2tp()
{
    local ip_version="$1"
    local l2tp_version="$2"
    local encap="$3"
    local pwtype="$4"
    local cookie_len="$5"
    local timeout="$6"
    local desc="$7"

    setup
    set -e
    setup_l2tp_session ${ip_version} $l2tp_version $encap $pwtype $cookie_len $timeout
    set +e

    run_ping $ip_version 0
    log_test $? 0 "${desc}"
    run_ping $ip_version 1600
    log_test $? 0 "${desc} (large packets)"
    cleanup
}

test_l2tpv3_cookie_mismatch()
{
    local ip_version=$1
    local encap=$2
    local cookie_len=$3
    local bad_cookie_len=$4
    local desc="$5"

    local bad_cookie=""
    test $bad_cookie_len -eq 4 && bad_cookie="11112222"
    test $bad_cookie_len -eq 8 && bad_cookie="1111222233334444"

    setup
    set -e
    setup_l2tp_session ${ip_version} 3 $encap eth $cookie_len 0 $bad_cookie
    set +e

    if test $ip_version -eq 4
    then
        run_cmd host-1 ping -c1 -w1 -I 172.16.101.1 172.16.101.2
    else
        run_cmd host-1 ${ping6} -c1 -w1 ${size_arg} -I fc00:101::1 fc00:101::2
    fi
    log_test $? 1 "cookie mismatch ${desc}"
    cleanup
}

# To test busy shutdown, the session interface is torn down after 2s
# while running a flood ping which fires data over the interfaces that
# will be torn down. If the netns can be successfully removed
# afterwards, it means that the L2TP session interfaces were
# successfully cleaned up and the test is deemed to have succeeded.
test_l2tp_busy_shutdown()
{
    local ip_version="$1"
    local l2tp_version="$2"
    local encap="$3"
    local pwtype="$4"
    local desc="$5"
    local ifname=""

    test "$pwtype" = "ppp" && ifname="ppp0" || ifname="l2tpeth0"

    setup
    set -e
    setup_l2tp_session ${ip_version} $l2tp_version $encap $pwtype 0 2
    set +e

    if test $ip_version -eq 4
    then
        run_cmd host-1 ping -q -f -w3 -I 172.16.101.1 172.16.101.2
    else
        run_cmd host-1 ${ping6} -q -f -w3 ${size_arg} -I fc00:101::1 fc00:101::2
    fi
    # ignore ping errors as we're checking for interface cleanup
    true

    cleanup
    run_cmd host-1 true || run_cmd host-2 true || run_cmd router true
    log_test $? 1 "busy shutdown ${desc}"
}

run_tests()
{
    cleanup
    test_l2tp 4 2 udp ppp 0 0 "L2TPv2 IPv4"
    test_l2tp 4 3 udp eth 0 0 "L2TPv3 IPv4 UDP eth"
    test_l2tp 4 3 ip eth 0 0 "L2TPv3 IPv4 IP eth"
    test_l2tp 4 3 udp ppp 0 0 "L2TPv3 IPv4 UDP ppp"
    test_l2tp 4 3 ip ppp 0 0 "L2TPv3 IPv4 IP ppp"
    test_l2tp 4 3 udp eth 4 0 "L2TPv3 IPv4 UDP eth, 4-byte cookie"
    test_l2tp 4 3 udp eth 8 0 "L2TPv3 IPv4 UDP eth, 8-byte cookie"
    test_l2tp 6 2 udp ppp 0 0 "L2TPv2 IPv6"
    test_l2tp 6 3 udp ppp 0 0 "L2TPv3 IPv6 UDP ppp"
    test_l2tp 6 3 udp eth 0 0 "L2TPv3 IPv6 UDP eth"
    test_l2tp 6 3 udp eth 4 0 "L2TPv3 IPv6 UDP eth, 4-byte cookie"
    test_l2tp 6 3 udp eth 8 0 "L2TPv3 IPv6 UDP eth, 8-byte cookie"
    test_l2tp 4 3 ip ppp 0 0 "L2TPv3 IPv4 IP ppp"
    test_l2tp 4 3 ip eth 0 0 "L2TPv3 IPv4 IP eth"
    test_l2tp 4 3 ip eth 4 0 "L2TPv3 IPv4 IP eth, 4-byte cookie"
    test_l2tp 4 3 ip eth 8 0 "L2TPv3 IPv4 IP eth, 8-byte cookie"
    test_l2tp 6 3 ip ppp 0 0 "L2TPv3 IPv6 IP ppp"
    test_l2tp 6 3 ip eth 0 0 "L2TPv3 IPv6 IP eth"
    test_l2tp 6 3 ip eth 4 0 "L2TPv3 IPv6 IP eth, 4-byte cookie"
    test_l2tp 6 3 ip eth 8 0 "L2TPv3 IPv6 IP eth, 8-byte cookie"
    test_l2tpv3_cookie_mismatch 4 udp 4 4 "L2TPv3 IPv4 UDP 4-byte cookie"
    test_l2tpv3_cookie_mismatch 6 udp 4 4 "L2TPv3 IPv6 UDP 4-byte cookie"
    test_l2tpv3_cookie_mismatch 4 ip 4 4 "L2TPv3 IPv4 IP 4-byte cookie"
    test_l2tpv3_cookie_mismatch 6 ip 4 4 "L2TPv3 IPv6 IP 4-byte cookie"
    test_l2tpv3_cookie_mismatch 4 udp 4 8 "L2TPv3 IPv4 UDP 8-byte cookie"
    test_l2tpv3_cookie_mismatch 6 udp 4 8 "L2TPv3 IPv6 UDP 8-byte cookie"
    test_l2tpv3_cookie_mismatch 4 ip 4 8 "L2TPv3 IPv4 IP 8-byte cookie"
    test_l2tpv3_cookie_mismatch 6 ip 4 8 "L2TPv3 IPv6 IP 8-byte cookie"
    test_l2tpv3_cookie_mismatch 4 udp 0 4 "L2TPv3 IPv4 UDP no cookie at peer"
    test_l2tpv3_cookie_mismatch 6 udp 0 4 "L2TPv3 IPv6 UDP no cookie at peer"
    test_l2tpv3_cookie_mismatch 4 ip 0 4 "L2TPv3 IPv4 IP no cookie at peer"
    test_l2tpv3_cookie_mismatch 6 ip 0 4 "L2TPv3 IPv6 IP no cookie at peer"
    test_l2tp_busy_shutdown 4 2 udp ppp "L2TPv2 IPv4"
    test_l2tp_busy_shutdown 4 3 udp eth "L2TPv3 IPv4 UDP eth"
    test_l2tp_busy_shutdown 4 3 ip eth "L2TPv3 IPv4 IP eth"
    test_l2tp_busy_shutdown 4 3 udp ppp "L2TPv3 IPv4 UDP ppp"
    test_l2tp_busy_shutdown 4 3 ip ppp "L2TPv3 IPv4 IP ppp"
    test_l2tp_busy_shutdown 6 2 udp ppp "L2TPv2 IPv6"
    test_l2tp_busy_shutdown 6 3 udp eth "L2TPv3 IPv6 UDP eth"
    test_l2tp_busy_shutdown 6 3 ip eth "L2TPv3 IPv6 IP eth"
    test_l2tp_busy_shutdown 6 3 udp ppp "L2TPv3 IPv6 UDP ppp"
    test_l2tp_busy_shutdown 6 3 ip ppp "L2TPv3 IPv6 IP ppp"
}

################################################################################
# main

declare -i nfail=0
declare -i nsuccess=0

while getopts :pv o
do
    case $o in
        p) PAUSE_ON_FAIL=yes;;
        v) VERBOSE=$(($VERBOSE + 1));;
        *) exit 1;;
    esac
done

run_tests

printf "\nTests passed: %3d\n" ${nsuccess}
printf "Tests failed: %3d\n"   ${nfail}
