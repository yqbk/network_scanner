require 'packetfu'

class Scaner

  def icmp_scan(ip)

    config = PacketFu::Utils.whoami?()

    # create icmp packet
    icmp_packet = PacketFu::ICMPPacket.new(:config => config)
    icmp_packet.ip_daddr = ip
    icmp_packet.payload = "ICPM probe"

    icmp_packet.icmp_type = 8 # echo

    icmp_packet.recalc

    capture_thread = Thread.new do
      begin
        Timeout::timeout(5) {
          cap = PacketFu::Capture.new(:iface => config[:iface], :start => true)
          cap.stream.each do |p|
            pkt = PacketFu::Packet.parse p
            next unless pkt.is_icmp?
            if pkt.ip_saddr == ip and pkt.icmp_type == 0 # echo reply form destintation host
              puts "#{ip} is up"
              break
            end
          end
        }
      rescue Timeout::Error
        puts "#{ip} is down"
      end
    end

    10.times do
      icmp_packet.to_w
    end

    capture_thread.join

  end

  def tcp_syn_scan(ip, port)

    config = PacketFu::Utils.whoami?()

    tcp_syn_packet = PacketFu::TCPPacket.new(:config => config)
    tcp_syn_packet.ip_daddr = ip
    tcp_syn_packet.payload = "TCP ack probe"

    tcp_syn_packet.tcp_flags.syn = 1
    tcp_syn_packet.tcp_dst = port
    tcp_syn_packet.tcp_src = 2000

    tcp_syn_packet.recalc

    capture_thread = Thread.new do
      begin
        Timeout::timeout(3) {
          cap = PacketFu::Capture.new(:iface => config[:iface], :start => true, :promisc => true) #promisc?
          cap.stream.each do |p|
            pkt = PacketFu::Packet.parse p
            next unless pkt.is_tcp?
            if pkt.ip_saddr == ip and pkt.ip_saddr == ip and pkt.tcp_dport ==  tcp_syn_packet.tcp_src and pkt.tcp_flags.syn == 1 and pkt.tcp_flags.ack == 1
              puts "#{ip} is up on port #{tcp_syn_packet.tcp_dst}"
              # print "Source Addr: #{pkt.ip_saddr}\n"
              # print "Destination Addr: #{pkt.ip_daddr}\n"
              # print "Destination Port: #{pkt.tcp_dport}\n"
              # print "TCP Options: #{pkt.tcp_options}\n"
              # print "TCP SYN?: #{pkt.tcp_flags.syn}\n"
              # print "TCP ACK?: #{pkt.tcp_flags.ack}\n"
              break
            end
          end
        }
      rescue Timeout::Error
        puts "  - #{ip} is down on port #{tcp_syn_packet.tcp_dst}"
      end
    end

    10.times do
      tcp_syn_packet.to_w
    end

    capture_thread.join
  end


  def tcp_fin_scan(ip, port)

    config = PacketFu::Utils.whoami?()

    tcp_fin_packet = PacketFu::TCPPacket.new(:config => config)
    tcp_fin_packet.ip_daddr = ip
    tcp_fin_packet.payload = "TCP ack probe"

    tcp_fin_packet.tcp_flags.fin = 1
    tcp_fin_packet.tcp_dst = port
    tcp_fin_packet.tcp_src = 2000

    tcp_fin_packet.recalc

    capture_thread = Thread.new do
      begin
        Timeout::timeout(3) {
          cap = PacketFu::Capture.new(:iface => config[:iface], :start => true) # :promisc => true
          cap.stream.each do |p|
            pkt = PacketFu::Packet.parse p
            next unless pkt.is_ip? or pkt.is_tcp?
            if pkt.ip_saddr == ip and pkt.ip_saddr == ip and pkt.tcp_dport == tcp_fin_packet.tcp_src and pkt.tcp_flags.rst == 1
              puts "  - #{ip} is down on port #{tcp_fin_packet.tcp_dst}"
              break
            end
          end
        }
      rescue Timeout::Error
        puts "#{ip} is up on port #{tcp_fin_packet.tcp_dst}"
      end
    end

    10.times do
      tcp_fin_packet.to_w
    end

    capture_thread.join
  end
#   class-------------------
end


scanner = Scaner.new

# (6..7).each do |host|
#   (1..30).each do |port|
#     scanner.tcp_fin_scan("192.168.0." + host.to_s, port)
#   end
# end
[22, 17600, 17603, 3306, 139, 53, 631, 5432, 17500, 445].each do |port|
  scanner.tcp_fin_scan("192.168.0.10", port)
end

