#!/usr/bin/env ruby
# encoding: ASCII-8BIT

require_relative 'packet'

module DHCP # :nodoc:
  class Client
    def initialize(opt={})
      @mac   = opt[:mac]
      @sock  = opt[:sock]
      @lease = nil
    end
    attr_accessor :mac

    def _parse_packet(data)
      pk = DHCP::Packet.new(data)
      data
    end

    def run
    end
  end
end

