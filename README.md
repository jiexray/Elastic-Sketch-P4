# Implementing MRI

## Introduction

This project is to implement a simple version of Elastic Sketch in SIGCOMM 2018 with P4. 

## Description of each file

1. `Makefile`: the compiling file. Note that the program is running under the enviornment of [P4 tutorial](https://github.com/p4lang/tutorials).

2. `receive_caida.py`: using Scapy to receive CAIDA trace packets.

3. `receive_query.py`: using Scapy to receive query packets (something like In-band Telemetry).

4. `s1-runtime.py`: config the routing in `s1`, which need to seperate the flow of CAIDA trace and query.

5. `splitted`: pcap file with 15M.

6. `test10P`: pcap file with 10 packets, 8 packet with 1 occurence, 1 packet with 2 occurence

7. `test1M`: pcap file with 1M.

8. `topology.json`: topology file for mininet, the net has 4 hosts (`h1`, `h2`, `h11`, `h22`) and 1 switch (`s1`).

   + `h1`: send CAIDA trace, using `tcpreply -i h1-eth0 -K test10P`
   + `h2`: receive CAIDA trace, using `./receive_caida.py`
   + `h3`: send query trace, using `./send_query.py`
   + `h4`: receive query trace, using `./receive_query.py`

9. `ES_heavy.p4`: implement of Elastic Sketch.

## The framework

Currently, I use `BMV2` to run the test. The sketches is saved in `extern Register`. Unfortunately, `P4 Runtime` does
not support acquire `Register` state. Therefore, I use a way like `In-band Telemetry (INT)` to query the state of Elastic
Sketch in the P4 switch.

Another issue is that CAIDA traces do not have Ethernet packet. This is not a problem for software switch like OVS used by 
mininet. I can also send the packets in CAIDA traces withour adding a fake Ethernet header. Thus, when I process packets from 
CAIDA traces, I ignore the Ethernet header. However, everything is not OK. When I send a query packet with Scapy, I attach an 
Ethernet header for easy processing. This time the query packet cannot be processed using the CAIDA packet processing pipeline.

I find a wayout with the help of P4 community. P4 can parse packet based on `ingress_port`. So I send CAIDA packet to `s1` from 
port `s1-eth2` (connect to `h1`), and send query packet to `s1` from `s1-eth1` (connected to `h11`). In deparsing phrase, I simply 
send all headers (Ethernet, IPv4, ...) all to the egress_port. 

I manually set the `ip_protocol` of query packets. If it is a query packet, it will send to `s1-eth3` (connect to `h22`). otherwise 
it will go to `s1-eth4` (connect to `h2`).

## Step 3: Query packet

In query packet, I manually set the `ip_protocol` to `63`, and push the real `ip_protocol` to a field in `IP_option`. 
The count value is also saved in `IP_option`.

```
got a packet
###[ Ethernet ]###
  dst       = ff:ff:ff:ff:ff:ff
  src       = 00:00:00:00:01:0b
  type      = 0x800
###[ IP ]###
     version   = 4L
     ihl       = 6L
     tos       = 0x0
     len       = 24
     id        = 1
     flags     = 
     frag      = 0L
     ttl       = 64
     proto     = 63
     chksum    = 0xc450
     src       = 16.241.200.171
     dst       = 64.5.155.180
     \options   \
      |###[ QUERY ]###
      |  copy_flag = 0L
      |  optclass  = control
      |  option    = 31L
      |  count     = 2
      |  flow_proto= 6

```

