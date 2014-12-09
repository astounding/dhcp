#!/usr/bin/env ruby
# encoding: ASCII-8BIT

require_relative 'packet'

module DHCP # :nodoc:
  class Server
    def initialize(opt={})
      @socket   = nil                    ## UDP server socket
      @interval = opt[:interval] || 0.5  ## Sleep interval
    end
    attr_reader :socket

    ## Main server event loop (non-blocking):
    def run_once
    end

    ## Main server event loop (blocking):
    def run
      loop do
        resut = run_once
        sleep @interval if !result  ## Sleep if no data was received and no errors occured
      end
    end

    ## Hand off raw UDP packet data here for parsing and dispatch:
    def dispatch_packet(data, source_ip, source_port)
      now = Time.now
      Syslog.info("Packet (#{data.size} bytes) from [#{source_ip}]:#{source_port} received at #{now}")
      if data.size < 300
        Syslog.info("Ignoring small packet (less than BOOTP minimum size.")
        return
      end

      packet = nil
      begin
        packet = DHCP::Packet.new(data)
      rescue => e
        show_packet(packet)
        Syslog.err("Error parsing DHCP packet.") 
        return
      end

      relay = nil
      if source_port == 67     ## DHCP relay via an intermediary
        relay = true

        ## Quick relay sanity-check on GIADDR:
        if packet.giaddr == IPAddress.new('0.0.0.0')
          Syslog.err("Packet from relay (port 67) has no GIADDR address set.  Ignoring.")
          return
        end

        unless relay_authorized?(source_ip, packet.giaddr)
          Syslog.err("Ignoring DHCP packet from unauthorized relay [#{source_ip}].")
          return
        end
      elsif source_port == 68  ## DHCP on directly attached subnet
        relay = false

        ## Quick relay sanity-check on GIADDR:
        if packet.giaddr != IPAddress.new('0.0.0.0')
          Syslog.err("Direct (non-relay) packet has set GIADDR to [#{packet.giaddr}] in violation of RFC. Ignoring.")
          return
        end
      else
        Syslog.err("Ignoring packet from UDP port other than 67 (relay) or 68 (direct)")
        return
      end

      ## Ethernet hardware type sanity check:
      if packet.htype != DHCP::HTYPE[:htype_10mb_ethernet][0] || packet.hlen !=  DHCP::HTYPE[:htype_10mb_ethernet][1]
        Syslog.err("Request hardware type or length doesn't match ETHERNET type and length. Ignoring.")
        return
      end

      if packet.op != DHCP::BOOTREQUEST
        Syslog.err("Recived a non-BOOTREQUEST packet.  Ignoring.")
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
        show_packet(packet)
        Syslog.err("Packet type #{packet.type_name} in a BOOTREQUEST is invalid.")
      else
        show_packet(packet)
        Syslog.err("Invalid, unknown, or unhandled DHCP packet type received.")
      end
    end

    def relay_authorized?(source_ip, giaddr)
      true
    end

    ## Handle DHCPDISCOVER packet:
    def handle_discover(packet, source_ip, relay)
      show_packet(packet)
      Syslog.info("handle_discover")
    end

    ## Handle DHCPREQUEST packet:
    def handle_request(packet, source_ip, relay)
      show_packet(packet)
      Syslog.info("handle_request")
    end

    ## Handle DHCPINFORM packet:
    def handle_inform(packet, source_ip, relay)
      show_packet(packet)
      Syslog.info("handle_inform")
    end

    ## Handle DHCPDECLINE packet:
    def handle_decline(packet, source_ip, relay)
      show_packet(packet)
      Syslog.info("handle_decline")
    end

    ## Handle DHCPLEASEQUERY packet:
    def handle_leasequery(packet, source_ip, relay)
      show_packet(packet)
      Syslog.info("handle_leasequery")
    end
  end

end

