#!/usr/bin/env ruby
# encoding: ASCII-8BIT

require 'socket'
require 'syslog'
require_relative 'packet'

module DHCP # :nodoc:
  class Server
    ZERO_IP = IPAddress('0.0.0.0')

    def initialize(opt={})
      @interval    = opt[:interval] || 0.5          ## Sleep (seconds) if no data
      @log         = opt[:log]      || Syslog       ## Logging object (should be open already)
      @server_ip   = opt[:ip]       || '0.0.0.0'    ## Listen on this IP
      @server_port = opt[:port]     || 67           ## Listen on this UDP port
      @debug       = opt[:debug]    || false

      ## Bind to UDP server port:
      @log.info("Starting DHCP on [#{@server_ip}]:#{@server_port} server at #{Time.now}")
      @sock = UDPSocket.new
      @sock.do_not_reverse_lookup = true
      @sock.setsockopt(Socket::SOL_SOCKET, Socket::SO_BROADCAST, true) ## Permit sending to broadcast address
      unless @sock.bind(@server_ip, 67)
        raise "Failed to bind"
      end
    end

    ## Main server event single-iteration function (non-blocking):
    def run_once
      r,w,e = IO.select([@sock], nil, [@sock], 0)
      if !r.nil? && r.size == 1
        data, src = @sock.recvfrom_nonblock(1500)
        if data.bytesize < 300
          @log.debug("Ignoring packet smaller than BOOTP minimum size") if @debug
        else
          dispatch_packet(data, src[3], src[1])
        end
        return true
      end
      if !e.nil? && e.size == 1
        ## TODO: Handle errors...
        raise "Unhandled error on socket"
      end
      return false
    end

    ## Main server event loop (blocking):
    def run
      loop do
        result = run_once
        sleep @interval if !result  ## Sleep if no data was received and no errors occured
      end
    end

    def show_packet(pk)
      @log.debug(">>> PACKET: #{pk.type} '#{pk.type_name}' at #{Time.now} >>>")
      pk.to_s.gsub(/\\/,'\\\\').gsub(/[^\x20-\x7e\n]/){|x| '\x' + x.unpack('H2')[0].upcase}.split("\n").each do |i|
        @log.debug("..." + i)
      end
      @log.debug("<<< END OF PACKET <<<")
    end

    ## Hand off raw UDP packet data here for parsing and dispatch:
    def dispatch_packet(data, source_ip, source_port)
      now = Time.now
      @log.debug("Packet (#{data.size} bytes) from [#{source_ip}]:#{source_port} received at #{now}")
      if data.size < 300
        @log.debug("Ignoring small packet (less than BOOTP minimum size.") if @debug
        return
      end

      packet = nil
      begin
        packet = DHCP::Packet.new(data)
      rescue => e
        show_packet(packet) if @debug
        @log.debug("Error parsing DHCP packet.") if @debug
        return
      end

      relay = nil
      if source_port == 67     ## DHCP relay via an intermediary
        relay = true

        ## Quick relay sanity-check on GIADDR:
        if packet.giaddr == ZERO_IP
          @log.debug("Packet from relay (port 67) has no GIADDR address set.  Ignoring.") if @debug
          return
        end

        unless relay_authorized?(source_ip, packet.giaddr)
          @log.debug("Ignoring DHCP packet from unauthorized relay [#{source_ip}].") if @debug
          return
        end
      elsif source_port == 68  ## DHCP on directly attached subnet
        relay = false

        ## Quick relay sanity-check on GIADDR:
        if packet.giaddr != ZERO_IP
          @log.debug("Direct (non-relay) packet has set GIADDR to [#{packet.giaddr}] in violation of RFC. Ignoring.") if @debug
          return
        end
      else
        @log.debug("Ignoring packet from UDP port other than 67 (relay) or 68 (direct)") if @debug
        return
      end

      ## Ethernet hardware type sanity check:
      if packet.htype != DHCP::HTYPE[:htype_10mb_ethernet][0] || packet.hlen !=  DHCP::HTYPE[:htype_10mb_ethernet][1]
        @log.debug("Request hardware type or length doesn't match ETHERNET type and length. Ignoring.") if @debug
        return
      end

      if packet.op != DHCP::BOOTREQUEST
        @log.debug("Recived a non-BOOTREQUEST packet.  Ignoring.") if @debug
        return
      end

      ## Dispatch packet:
      case packet.type
      when DHCP::DHCPDISCOVER
        handle_discover(packet, source_ip, relay)
      when DHCP::DHCPREQUEST
        handle_request(packet, source_ip, relay)
      when DHCP::DHCPINFORM
        handle_inform(packet, source_ip, relay)
      when DHCP::DHCPRELEASE
        handle_release(packet, source_ip, relay)
      when DHCP::DHCPDECLINE
        handle_decline(packet, source_ip, relay)
      when DHCP::DHCPLEASEQUERY
        handle_leasequery(packet, source_ip, relay)
      when DHCP::DHCPOFFER, DHCP::DHCPACK, DHCP::DHCPNAK, DHCP::DHCPFORCERENEW, DHCP::DHCPLEASEUNASSIGNED, DHCP::DHCPLEASEACTIVE, DHCP::DHCPLEASEUNKNOWN
        show_packet(packet) if @debug
        @log.debug("Packet type #{packet.type_name} in a BOOTREQUEST is invalid.") if @debug
      else
        show_packet(packet) if @debug
        @log.debug("Invalid, unknown, or unhandled DHCP packet type received.") if @debug
      end
    end

    def relay_authorized?(source_ip, giaddr)
      true
    end

    ## Handle DHCPDISCOVER packet:
    def handle_discover(packet, source_ip, relay)
      show_packet(packet) if @debug
      @log.debug("handle_discover") if @debug
    end

    ## Handle DHCPREQUEST packet:
    def handle_request(packet, source_ip, relay)
      show_packet(packet) if @debug
      @log.debug("handle_request") if @debug
    end

    ## Handle DHCPINFORM packet:
    def handle_inform(packet, source_ip, relay)
      show_packet(packet) if @debug
      @log.debug("handle_inform") if @debug
    end

    ## Handle DHCPDECLINE packet:
    def handle_decline(packet, source_ip, relay)
      show_packet(packet) if @debug
      @log.debug("handle_decline") if @debug
    end

    ## Handle DHCPLEASEQUERY packet:
    def handle_leasequery(packet, source_ip, relay)
      show_packet(packet) if @debug
      @log.debug("handle_leasequery") if @debug
    end
  end

end

