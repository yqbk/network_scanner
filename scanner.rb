require 'packetfu'

class Scanner

  private
    @ip
    @dst
    @src
    @timeout_value
    @tries
    @config

  def initialize(ip, dst, src, timeout_value, tries)

    @ip = ip
    @dst = dst
    @src = src
    @timeout_value = timeout_value
    @tries = tries
    @config = PacketFu::Utils.whoami?()

    @prepared_packet = prepare
  end

  def prepare

    packet = PacketFu::TCPPacket.new(:config => @config)
    packet.ip_daddr = @ip
    packet.tcp_dst = @dst
    packet.tcp_src = @src

    additional_config(packet)

    packet.recalc

    packet
  end

  def additional_config(packet)
    packet.payload = "TCP sny probe"
    packet.tcp_flags.syn = 1
    packet
  end

  def check_packet_type(pkt)
    pkt.is_tcp?
  end

  def check(pkt)
    pkt.ip_saddr == @ip and pkt.tcp_dport ==  @prepared_packet.tcp_src and pkt.tcp_flags.syn == 1 and pkt.tcp_flags.ack == 1
  end

  def on_check_success
    puts "#{@ip} is up"
  end

  def on_timeout
    puts "#{@ip} is down"
  end

  public

  def scann

    capture_thread = Thread.new do
    begin
      Timeout::timeout(@timeout_value) {
        cap = PacketFu::Capture.new(:iface => @config[:iface], :start => true)
        cap.stream.each do |p|
          pkt = PacketFu::Packet.parse p
          next unless check_packet_type(pkt)
          if check(pkt)
            on_check_success
            break
          end
        end
      }
    rescue Timeout::Error
      on_timeout
    end
  end
  @tries.times do
    @prepared_packet.to_w
  end
  capture_thread.join
  end


end

ip = "192.168.0.2"
dst = 80
src = 999
timeout_value = 3
tries = 10
scanner = Scanner.new(ip, dst, src, timeout_value, tries)

scanner.scann