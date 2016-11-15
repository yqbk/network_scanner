require 'packetfu'

class Scaner

  def icmp_scan(ip)

    config = PacketFu::Utils.whoami?()

    # create icmp packet
    icmp_packet = PacketFu::ICMPPacket.new(:config => config)
    icmp_packet.ip_daddr = ip
    icmp_packet.payload = "Probe"
    icmp_packet.icmp_type = 8 # echo
    icmp_packet.recalc

    capture_thread = Thread.new do
      begin
        Timeout::timeout(1) {
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
end

scanner = Scaner.new

(1..10).each do |host|
  scanner.icmp_scan("192.168.0." + host.to_s)
end

