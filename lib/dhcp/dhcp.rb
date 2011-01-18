# encoding: ASCII-8BIT
#
# --
#
# Ruby DHCP module for parsing and creating IPv4 DHCP packets
# - See http://www.aarongifford.com/computers/dhcp/
#
# --
#
# Written by Aaron D. Gifford - http://www.aarongifford.com/
#
# Copyright (c) 2010-2011 InfoWest, Inc. and Aaron D. Gifford
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#
# --
#
# NOTE: All strings in this module should be BINARY (ASCII-8BIT) encoded
#       or things won't work correctly.
#

## Monkeypatch String so it will have a working #ord method (for 1.8):
unless RUBY_VERSION >= '1.9.1'
  class String
    def ord
      self[0]
    end
  end
end

## http://github.org/bluemonk/ipaddress - A very nice IP address utility gem
require 'ipaddress'

module DHCP
  ## Base class from which all DHCP options in a DHCP packet derive:
  class Opt
    def initialize(opt, name, ignore=nil)
      @opt  = opt
      @name = name
    end
    attr_reader :opt, :name

    def opt_header
      "OPTION[#{opt}:#{@name}]"
    end

    def to_s
      opt_header
    end

    def to_opt
      @opt.chr
    end
  end


  ## Class for DHCP options that contain data
  class OptData < Opt
    def initialize(opt, name, data=nil)
      super(opt, name)
      @data = data.nil? ? '' : data_to_bin(data)
    end
    attr_accessor :data

    def data
      @data
    end

    def data=(data)
      @data = data.dup
      self ## Chainable
    end

    def set(data)
      self.data = data_to_bin(data)
      self ## Chainable
    end

    def get
      bin_to_data(@data)
    end

    def data_to_bin(data)  ## Override this in subclasses to interpret data
      data
    end

    def bin_to_data(data)  ## Override this in subclasses to interpret data
      data
    end

    def opt_header
      super + "(#{data.size})"
    end

    def to_s
      opt_header + "='#{bin_to_data(@data)}'"
    end

    def to_opt
      super + @data.size.chr + @data
    end
  end 


  ## Class for DHCP options containing a fixed number of bytes
  class OptFixedData < OptData
    @size = 0   ## Override this in subclasses
    class << self
      attr_accessor :size
    end

    def initialize(opt, name, data=nil)
      super(opt, name, data)
      ## Prefill with zeros if needed:
      @data = 0.chr * self.class.size if data.nil? && self.class.size > 0
    end

    def data=(data)
      raise "Invalid size for #{self.class} (expected #{size} bytes, not #{data.size} bytes)" unless self.class.size == data.size
      super(data)
    end
  end

  ## Class for DHCP options that contain a lists (like lists of IPs)
  class OptListData < OptData
    include Enumerable
    def initialize(opt, name, data=nil)
      super(opt, name)
      @size = 0
      set(data) unless data.nil?
    end

    def data=(data)
      set(split_data(data))
    end

    def get
      split_data(@data)  ## Splits and interprets binary data
    end

    def set(list)
      list = [list] unless is_list?(list)
      @data = ''
      @size = 0
      list.each do |item|
        append(item)
      end
      self ## Chainable
    end

    def is_list?(list) ## Override if needed in child class
      list.is_a?(Array)
    end

    def append(item)
      @size += 1
      @data += data_to_bin(item)
      self ## Chainable
    end

    def split_data(data) ## Override in child class to split and interpret binary data
      raise "Child class #{data.class} MUST override this"
    end

    def size
      @size
    end

    def to_s
      opt_header + '=[' + map{|x| x.to_s}.join(',') + ']'
    end

    def each
      split_data(@data).each do |item|
        yield item
      end
    end
  end

  ## Class for DHCP option suboptions:
  class SubOpt < OptData
    def opt_header
      "suboption[#{opt}:#{@name}]"
    end
  end

  ## Class for DHCP option suboptions containing lists
  class SubOptList < OptListData
    def opt_header
      "suboption[#{opt}:#{@name}]"
    end
  end

  ## Class for DHCP suboption for vendor specific information
  class SubOptVSRInfo < SubOptList
    def is_list?(list)
      raise "Invalid suboption sublist/entry" unless list.is_a?(Array)
      return false if list.size == 2 && list[0].is_a?(Fixnum) && list[1].is_a?(String)
      list.each do |item|
        raise "Invalid suboption sublistlist" unless item.is_a?(Array) && item.size == 2 && item[0].is_a?(Fixnum) && item[1].is_a?(String)
      end
      return true
    end

    def split_data(data)
      data = data.dup
      list = []
      while data.size > 0
        raise "Invalid suboption data" unless data.size >= 5
        len = data[4,1].ord
        raise "Invalid vendor-specific relay info. data length" unless data.size >= len + 5
        list << [ data[0,4].unpack('N')[0], data[5,len] ]
        data[0,5+len] = ''
      end
      list
    end

    def bin_to_data(data)
      raise "Invalid data size" unless data.size >= 5 && data.size == data[4,1].ord + 5
      [ data[0,1].ord, data[2,data.size-2] ]
    end

    def data_to_bin(data)
      raise "Invalid data" unless data.is_a?(Array) && data.size == 2 && data[0].is_a?(Fixnum) && data[1].is_a?(String)
      raise "Invalid data size" unless data[1].size < 256
      data[0].chr + data[1].size.chr + data[1]
    end
  end

  ## Class for DHCP options that contain sublists (like vendor specific information or relay agent information)
  class OptSubList < OptListData
    def is_list?(list)
      raise "Invalid suboption list/entry" unless list.is_a?(Array)
      return false if list.size == 2 && list[0].is_a?(Fixnum) && list[1].is_a?(String)
      list.each do |item|
        raise "Invalid suboption list" unless item.is_a?(Array) && item.size == 2 && item[0].is_a?(Fixnum) && item[1].is_a?(String)
      end
      return true
    end

    def split_data(data)
      data = data.dup
      list = []
      while data.size > 0
        raise "Invalid data size" unless data.size >= 2
        len = data[1,1].ord
        raise "Invalid data size" unless data.size >= len + 2
        list << [ data[0,1].ord, data[2,len] ]
        data[0,len+2] = ''
      end
      list
    end

    def bin_to_data(data)
      raise "Invalid data size" unless data.size >= 2 && data.size == data[1,1].ord + 2
      [ data[0,1].ord, data[2,data.size-2] ]
    end

    def data_to_bin(data)
      raise "Invalid data" unless data.is_a?(Array) && data.size == 2 && data[0].is_a?(Fixnum) && data[1].is_a?(String)
      raise "Invalid data size" unless data[1].size < 256
      data[0].chr + data[1].size.chr + data[1]
    end

    def to_s
      opt_header + "(#{@size})=[" + map do |i|
        val = ''
        name = case i[0]
        when 1
          val = i[1].scan(/./m).map{|b| b.unpack('H2')[0].upcase}.join(':')
          'AgentCircuitID'
        when 2
          val = i[1].scan(/./m).map{|b| b.unpack('H2')[0].upcase}.join(':')
          'AgentRemoteID'
        when 9
          val = (SubOptVSRInfo.new(9, :vendor_specific_relay_suboption).data=i[1]).to_s
          'VendorSpecificRelaySuboption'
        else
          val = i[1].scan(/./m).map{|b| b.unpack('H2')[0].upcase}.join(':')
          'Unknown'
        end
        "#{name}:#{i[0]}(#{i[1].size})='#{val}'"
      end.join(',') + ']'
    end
  end

  ## Class for DHCP options that contain lists of fixed sized data
  class OptListFixedData < OptListData
    @size = 0 ## Override this in subclasses
    class << self
      attr_accessor :size
    end

    def split_data(data)
      raise "Child class #{self.class} MUST override class size variable with non-zero value!" if self.class.size == 0
      raise "Invalid data length #{data.size} (expected even multiple of #{self.class.size})" unless data.size % self.class.size == 0
      list = []
      data = data.dup
      while data.size > 0
        list << bin_to_data(data.slice!(0,self.class.size))
      end
      list
    end

    def data_to_bin(item)  ## Override in child, but call super(item)
                           ## with the resulting translated data after
                           ## data translation so the size check is
                           ## applied (or do a size check in the child):
      raise "Invalid data item length #{item.size} (expected #{self.class.size})" unless item.size == self.class.size
      item
    end
  end

  ## Class for DHCP options that contain a single IPv4 address
  class OptIP < OptFixedData
    @size = 4

    def bin_to_data(data)
      IPAddress::IPv4::parse_data(data).to_s
    end

    def data_to_bin(data)
      IPAddress::IPv4.new(data).data   ## Will raise exception if data is not a valid IP
    end
  end

  ## Class for DHCP options that contain a list of IPv4 addresses
  class OptIPList < OptListFixedData
    @size = 4

    def bin_to_data(data)
      IPAddress::IPv4::parse_data(data).to_s
    end

    def data_to_bin(data)
      IPAddress::IPv4.new(data).data  ## Will raise exception if data is not a valid IP
    end
  end

  ## Class for DHCP option 33 (static routes) - Use option 121 instead if possible
  ## WARNING: Option 33 can only handle class A, B, or C networks, not classless
  ## networks with an arbitrary netmask.
  class OptStaticRoutes < OptListFixedData
    @size = 8

    def is_list?(list)
      raise "Invalid route list/entry" unless list.is_a?(Array)
      if list.size == 2
        return false if list[0].is_a?(String) && list[1].is_a?(String)
        return true  if list[0].is_a?(Array)  && list[1].is_a?(Array) 
        raise "Invalid route list/entry"
      end
      list.each do |item|
        raise "Invalid route list" unless item.is_a?(Array) && item[0].is_a?(String) && item[1].is_a?(String)
      end
      return true
    end

    def data_to_bin(data)
      raise "Invalid static route" unless data.is_a?(Array) && data.size == 2
      net, gateway = *data
      net = IPAddress::IPv4.new(net)
      raise "Invalid classful static route network" unless net.network?
      raise "Invalid classful static route network" unless (
        (net.a? && net.prefix == 8 ) ||
        (net.b? && net.prefix == 16) ||
        (net.c? && net.prefix == 24)
      )
      gateway = IPAddress::IPv4.new("#{gateway}/#{net.prefix}")
      raise "Invalid classful static route gateway" unless gateway.member?(net)
      net.data + gateway.data
    end

    def bin_to_data(data)
      [IPAddress::IPv4::parse_classful_data(data[0,4]).net.to_string,  IPAddress::IPv4::parse_data(data[4,4]).to_s]
    end

    def to_s
      opt_header + '=[' + map{|i| i[0] + '=>' + i[1]}.join(',') + ']'
    end
  end

  ## Class for DHCP options containing lists of IPv4 CIDR routes (like option 121 or MS's 249)
  ## See RFC 3442 "compact encoding" of destination
  class OptRouteList < OptListData
    def split_data(data)
      data = data.dup
      list = []
      while data.size > 0
        raise "Invalid binary data" unless data.size > 4 || data[0,1].ord > 32
        octets = (data[0,1].ord + 7)/8
        raise "Invalid binary data" unless data.size >= octets + 5
        list << bin_to_data(data.slice!(0,octets+5))
     end
     list
    end

    def data_to_bin(data)
      raise "Invalid classless static route" unless data.is_a?(Array) && data.size == 2
      net, gateway = *data
      raise "Invalid classless static route network" if net.index('/').nil?
      net = IPAddress::IPv4.new(net)
      raise "Invalid classless static route network" unless net.network?
      gateway = IPAddress::IPv4.new("#{gateway}/#{net.prefix}")
      raise "Invalid classless static route gateway" unless gateway.member?(net)
      net.prefix.to_i.chr + net.data[0,(net.prefix+7)/8] + gateway.data
    end

    def bin_to_data(data)
      raise "Invalid binary classless route data" unless data.size > 4 || data[0,1].ord > 32
      maskbits = data[0,1].ord
      octets   = (maskbits+7)/8
      raise "Invalid binary classless route data" unless data.size == octets + 5
      dest = IPAddress::IPv4.parse_data(data[1,octets] + 0.chr * (4 - octets))
      dest.prefix = maskbits
      gateway = IPAddress::IPv4.parse_data(data[octets+1,4])
      gateway.prefix = maskbits  ## Unnecessary...
      ## Should an "Invalid classless static route" exception be raised
      ## here if gateway is not a member of the destination network?
      [dest.to_string, gateway.to_s]
    end
  end

  ## Class for boolean DHCP options
  class OptBool < OptFixedData
    @size = 1

    def data_to_bin(data)
      raise "Invalid boolean data #{data.class} (expected TrueClass or FalseClass)" unless data.is_a?(TrueClass) || data.is_a?(FalseClass)
      data ? 1.chr : 0.chr
    end

    def bin_to_data(data)
      raise "Invalid boolean binary data" if data.size != 1 || data.ord > 1
      data.ord == 0 ? false : true
    end
  end

  ## Class for single-byte unsigned integer value DHCP options
  ## Also acts as parent class for multi-byte value DHCP options
  class OptByte < OptFixedData
    @size = 1

    def data_to_bin(data)
      raise "Invalid numeric data" unless data.is_a?(Fixnum) && data >= 0
      raise "Invalid number" unless data == data & ([0xff] * self.class.size).inject(0){|sum,byte| sum<<8|byte}
      bytes = ''
      while data != 0
        bytes = (data & 0xff).chr + bytes
        data >>= 8
      end
      raise "Impossible: Numeric byte size #{bytes.size} exceeds #{self.class.size}" if bytes.size > self.class.size
      0.chr * (self.class.size - bytes.size) + bytes
    end

    def bin_to_data(data)
      data.each_byte.inject(0){|sum,byte| sum<<8|byte}
    end

    def to_s
      opt_header + "=#{self.get}"
    end
  end

  ## Class for two-byte unsigned integer value DHCP options
  class OptInt16 < OptByte
    @size = 2
  end

  ## Class for four-byte unsigned integer value DHCP options
  class OptInt32 < OptByte
    @size = 4
  end

  ## Class for four-byte signed integer value DHCP options
  class OptSInt32 < OptInt32
    @size = 4
    def data_to_bin(data)
      super(data % 2**32)
    end

    def bin_to_data(data)
      (super(data) + 2**31) % 2**32 - 2**31
    end
  end

  ## Class for DHCP options containing a list of single byte integers (i.e. lists of requested DHCP options)
  class OptByteList < OptListFixedData
    @size = 1

    def bin_to_data(data)
      data.each_byte.inject(0){|sum,byte| sum<<8|byte}
    end

    def data_to_bin(data)
      raise "Invalid numeric data" unless data.is_a?(Fixnum) && data >= 0
      raise "Invalid number" unless data == data & ([0xff] * self.class.size).inject(0){|sum,byte| sum<<8|byte}
      bytes = ''
      while data != 0
        bytes = (data & 0xff).chr + bytes
        data >>= 8
      end
      raise "Impossible: Numeric byte size #{bytes.size} exceeds #{self.class.size}" if bytes.size > self.class.size
      0.chr * (self.class.size - bytes.size) + bytes
    end

    def to_s
      opt_header + '=[' + map{|x| x.to_s}.join(',') + ']'
    end
  end

  ## Class for DHCP options containing data that is most often displayed as a string of hexadecimal digit pairs joined by colons (i.e. ethernet MAC addresses)
  class OptHexString < OptData
    def data_to_bin(data)
      data.split(/[ \.:\-]/).map{|b| [('0'+b)[-2,2]].pack('H2')}.join
    end

    def bin_to_data(data)
      data.scan(/./m).map{|b| b.unpack('H2')[0].upcase}.join(':')
    end
  end

  ## Class for DHCP options containing DNS host names
  class OptHost < OptData
    def data_to_bin(data)
      raise "Invalid host name" unless /^(?:[a-zA-Z0-9][a-zA-Z0-9-]{0,62}\.)*[a-zA-Z0-9][a-zA-Z0-9-]{0,62}$/.match(data)
      data
    end
  end

  ## Class for DHCP options containing DNS domain names
  class OptDomain < OptData
    def data_to_bin(data)
      raise "Invalid domain name" unless /^(?:[a-zA-Z0-9][a-zA-Z0-9-]{0,62}\.)*[a-zA-Z0-9][a-zA-Z0-9-]{0,62}\.?$/.match(data)
    end
  end

  ## Class representing a DHCP packet (a request or a response):
  class Packet
    def initialize(op=nil)
      raise "Invalid/unsupported operation type #{op}" unless op.nil? || op == BOOTREQUEST || op == BOOTREPLY
      @op      = op || BOOTREQUEST     ## 1: Operation (BOOTREQUEST=1/BOOTREPLY=2)
      @htype_name = :htype_10mb_ethernet
      @htype   = HTYPE[@htype_name][0] ## 1: Hardware address type
      @hlen    = HTYPE[@htype_name][1] ## 1: Hardware address length
      @hops    = 0   ## 1: Client sets to zero, relays may increment
      @xid     = 0   ## 4: Client picks random XID (session ID of sorts)
      @secs    = 0   ## 4: Seconds elapsed since client started transaction
      @flags   = 0   ## 2: Leftmost bit is the 'BROADCAST' flag (if set) - Others are zero (reserved for future use)
      @ciaddr  = 0.chr * 4 ## 4: "Client IP"  -- Only set by client if client state is BOUND/RENEW/REBINDING and client can respond to ARP requests
      @yiaddr  = 0.chr * 4 ## 4: "Your IP"    -- Server assigns IP to client
      @siaddr  = 0.chr * 4 ## 4: "Server IP"  -- IP of server to use in NEXT step of client bootstrap process
      @giaddr  = 0.chr * 4 ## 4: "Gateway IP" -- Relay agent will set this to itself and modify replies
                     ## 16: Client hardware address (see htype and hlen)
      @chaddr  = 0.chr * @hlen  ## ^^^ See note above ^^^
      @sname   = ''  ## 64: Server host name (optional) as C-style null/zero terminated string (may instead contain options)
      @file    = ''  ## 128: Boot file name (optional) as C-style null/zero terminated string (may instead contain options)
      @options = ''  ## variable: Options - Up to 312 bytes in a 576-byte DHCP message - First four bytes are MAGIC
      @optlist = []
      @type    = nil ## Unknown until set
      @type_name = 'UNKNOWN'
    end
    attr_reader :op, :htype_name, :htype, :hlen, :hops, :xid, :secs, :flags, :type, :type_name, :options, :optlist
    attr_accessor :secs, :xid, :sname, :file

    def initialize_copy(orig)
      self.ciaddr = orig.ciaddr
      self.yiaddr = orig.yiaddr
      self.siaddr = orig.siaddr
      self.giaddr = orig.giaddr
      @chaddr  = orig.raw_chaddr.dup
      @file    = orig.file.dup
      @sname   = orig.sname.dup
      @options = orig.options.dup
      @optlist = []
      orig.optlist.each do |opt|
        @optlist << opt.dup
      end
    end

    def append_opt(opt)
      if opt.name == :dhcp_message_type
        unless @type.nil?
          raise "DHCP message type ALREADY SET in packet"
        end
        set_type(opt)
      end
      @optlist << opt
    end

    def _find_htype(htype)
      HTYPE.each do |name, htype|
        if htype[0] == @htype
          return name
        end
      end
      return nil
    end

    def parse(msg)
      raise "Packet is too short (#{msg.size} < 241)" if (msg.size < 241)
      @op    = msg[0,1].ord
      raise 'Invalid OP (expected BOOTREQUEST or BOOTREPLY)' if @op != BOOTREQUEST && @op != BOOTREPLY
      self.htype = msg[1,1].ord  ## This will do sanity checking and raise an exception on unsupported HTYPE
      raise "Invalid hardware address length #{msg[2,1].ord} (expected #{@hlen})" if msg[2,1].ord != @hlen
      @hops   = msg[3,1].ord
      @xid    = msg[4,4].unpack('N')[0]
      @secs   = msg[8,2].unpack('n')[0]
      @flags  = msg[10,2].unpack('n')[0]
      @ciaddr = msg[12,4]
      @yiaddr = msg[16,4]
      @siaddr = msg[20,4]
      @giaddr = msg[24,4]
      @chaddr = msg[28,16]
      @sname  = msg[44,64]
      @file   = msg[108,128]
      magic   = msg[236,4]
      raise "Invalid DHCP OPTION MAGIC #{magic.each_byte.map{|b| ('0'+b.to_s(16).upcase)[-2,2]}.join(':')} !=  #{MAGIC.each_byte.map{|b| ('0'+b.to_s(16).upcase)[-2,2]}.join(':')}" if magic != MAGIC
      @options = msg[240,msg.size-240]
      @optlist = []
      parse_opts(@options)
      opt = get_option(:option_overload)
      unless opt.nil?
        ## RFC 2131: If "option overload" present, parse FILE field first, then SNAME (depending on overload value)
        parse_opts(@file)  if opt.get == 1 || opt.get == 3
        parse_opts(@sname) if opt.get == 2 || opt.get == 3
        raise "Invalid option overload value" if opt.val > 1 || opt.val > 3
      end
      opt = get_option(:dhcp_message_type)
      raise "Not a valid DHCP packet (may be BOOTP): Missing DHCP MESSAGE TYPE" if opt.nil?
      set_type(opt)
    end

    def set_type(opt)
      @type = opt.get
      case @type
      when DHCPDISCOVER
        @type_name = 'DHCPDISCOVER'
        raise "Invalid OP #{@op} for #{@type_name}" unless @op == BOOTREQUEST
      when DHCPOFFER
        @type_name = 'DHCPOFFER'
        raise "Invalid OP #{@op} for #{@type_name}" unless @op == BOOTREPLY
      when DHCPREQUEST
        @type_name = 'DHCPREQUEST'
        raise "Invalid OP #{@op} for #{@type_name}" unless @op == BOOTREQUEST
      when DHCPDECLINE
        @type_name = 'DHCPDECLINE'
        raise "Invalid OP #{@op} for #{@type_name}" unless @op == BOOTREQUEST
      when DHCPACK
        @type_name = 'DHCPACK'
        raise "Invalid OP #{@op} for #{@type_name}" unless @op == BOOTREPLY
      when DHCPNAK
        @type_name = 'DHCPNAK'
        raise "Invalid OP #{@op} for #{@type_name}" unless @op == BOOTREPLY
      when DHCPRELEASE
        @type_name = 'DHCPRELEASE'
        raise "Invalid OP #{@op} for #{@type_name}" unless @op == BOOTREQUEST
      when DHCPINFORM
        @type_name = 'DHCPINFORM'
        raise "Invalid OP #{@op} for #{@type_name}" unless @op == BOOTREQUEST
      when DHCPFORCERENEW
        @type_name = 'DHCPFORCERENEW'
        raise "Invalid OP #{@op} for #{@type_name}" unless @op == BOOTREPLY
      when DHCPLEASEQUERY
        @type_name = 'DHCPLEASEQUERY'
        raise "Invalid OP #{@op} for #{@type_name}" unless @op == BOOTREQUEST
      when DHCPLEASEUNASSIGNED
        @type_name = 'DHCPLEASEUNASSIGNED'
        raise "Invalid OP #{@op} for #{@type_name}" unless @op == BOOTREPLY
      when DHCPLEASEUNKNOWN
        @type_name = 'DHCPLEASEUNKNOWN'
        raise "Invalid OP #{@op} for #{@type_name}" unless @op == BOOTREPLY
      when DHCPLEASEACTIVE
        @type_name = 'DHCPLEASEACTIVE'
        raise "Invalid OP #{@op} for #{@type_name}" unless @op == BOOTREPLY
      else
        raise "Invalid DHCP MESSAGE TYPE" if opt.val < 1 || opt.val > 8
      end
    end

    ## Look through a packet's options for the option in question:
    def get_option(opt)
      @optlist.each do |o|
        return o if (opt.is_a?(Symbol) && o.name == opt) || (opt.is_a?(Fixnum) && o.opt == opt)
      end
      nil
    end

    def parse_opts(opts)
      msg = opts.dup
      while msg.size > 0
        opt = msg[0,1].ord
        if opt == 0
          ## Don't add padding options to our list...
          msg[0,1] = ''
        elsif opt == 255 
          ## Options end...  Assume all the rest is padding (if any)
          @optlist << Opt.new(255, :end)
          msg = ''
        else
          ## TODO: If an option value can't fit within a single option,
          ## it may span several and the values should be merged.  We
          ## don't support this yet for parsing.
          raise "Options end too soon" if msg.size == 1
          len = msg[1,1].ord
          raise "Options end too abruptly (expected #{len} more bytes, but found only #{msg.size - 2})" if msg.size < len + 2
          val = msg[2,len]
          msg[0,len+2] = ''
          o = get_option(opt)
          if o.nil?
            o = DHCP::make_opt(opt)
            if o.nil?
              puts "WARNING: Ignoring unsupported option #{opt} (#{len} bytes)"
            else
              o.data = val unless len == 0
              @optlist << o
            end
          else
            ## See above TODO note...
            puts "WARNING: Duplicate option #{opt} (#{o.name}) of #{len} bytes skipped/ignored"
          end
        end
      end
    end

    def to_packet
      packet =
        @op.chr + @htype.chr + @hlen.chr + @hops.chr +
        [@xid, @secs, @flags].pack('Nnn') +
        @ciaddr + @yiaddr + @siaddr + @giaddr +
        @chaddr + (0.chr * (16-@chaddr.size)) +
        @sname  + (0.chr * (64-@sname.size)) +
        @file   + (0.chr * (128-@file.size)) +
        MAGIC +
        @optlist.map{|x| x.to_opt}.join
      packet + (packet.size < 300 ? 0.chr * (300 - packet.size) : '')  ## Pad to minimum of 300 bytes (BOOTP min. packet size)
    end

    def to_s
      str = "op=#{@op} "
      case @op
      when BOOTREQUEST
        str += '(BOOTREQUEST)'
      when BOOTREPLY
        str += '(BOOTREPLY)'
      else
        str += '(UNKNOWN)'
      end
      str += "\n"

      str += "htype=#{@htype} "
      found = false
      HTYPE.each do |name, htype|
        if htype[0] == @htype
          found = true
          str += name.to_s.upcase + "\n" + 'hlen=' + htype[1].to_s + "\n"
          str += "*** INVALID HLEN #{@hlen} != #{htype[1]} ***\n" if @hlen != htype[1]
          break
        end
      end
      str += "UNKNOWN\nhlen=" + @hlen.to_s + "\n"  unless found
      str += "hops=#{@hops}\n"
      str += "xid=#{@xid} (0x" + [@xid].pack('N').each_byte.map{|b| ('0'+b.to_s(16).upcase)[-2,2]}.join + ")\n"
      str += "secs=#{@secs}\n"
      str += "flags=#{@flags} (" + (broadcast? ? 'BROADCAST' : 'NON-BROADCAST') + ")\n"
      str += 'ciaddr=' + ciaddr + "\n"
      str += 'yiaddr=' + yiaddr + "\n"
      str += 'siaddr=' + siaddr + "\n"
      str += 'giaddr=' + giaddr + "\n"
      str += 'chaddr=' + chaddr + "\n"
      str += "sname='#{@sname.sub(/\x00.*$/,'')}' (#{@sname.sub(/\x00.*$/,'').size})\n"
      str += "file='#{@file.sub(/\x00.*$/,'')}' (#{@file.sub(/\x00.*$/,'').size})\n"
      str += 'MAGIC: (0x' + MAGIC.each_byte.map{|b| ('0'+b.to_s(16).upcase)[-2,2]}.join + ")\n"
      str += "OPTIONS(#{@optlist.size}) = [\n  "
      str += @optlist.map{|x| x.to_s}.join(",\n  ") + "\n]\n"
      str += "DHCP_PACKET_TYPE='#{@type_name}' (#{@type}) " unless @type.nil?
      str
    end

    def htype=(htype)
      @htype_name = _find_htype(htype)
      raise "Invalid/unsupported hardware type #{htype}" if @htype_name.nil?
      @hlen = HTYPE[@htype_name][1]
      @htype = HTYPE[@htype_name][0]
    end

    ## Broadcast flag:
    def broadcast?
      @flags & 0x8000 != 0
    end
    def broadcast!
      @flags |= 0x8000
    end

    ## Hardware address (ethernet MAC style):
    def chaddr
      @chaddr[0,@hlen].each_byte.map{|b| ('0'+b.to_s(16).upcase)[-2,2]}.join(':')
    end
    def raw_chaddr
      @chaddr
    end
    def chaddr=(addr)
      raise "Invalid hardware address" if addr.size - @hlen + 1 != @hlen * 2 || !/^(?:[a-fA-F0-9]{2}[ \.:_\-])*[a-fA-F0-9]{2}$/.match(addr)
      @chaddr = addr.split(/[ .:_-]/).map{|b| b.to_i(16).chr}.join
    end

    ## IP accessors:
    def ciaddr
      IPAddress::IPv4::parse_data(@ciaddr).to_s
    end
    def ciaddr=(ip)
      @ciaddr = IPAddress::IPv4.new(ip).data
    end

    def yiaddr
      IPAddress::IPv4::parse_data(@yiaddr).to_s
    end
    def yiaddr=(ip)
      @yiaddr = IPAddress::IPv4.new(ip).data
    end

    def siaddr
      IPAddress::IPv4::parse_data(@siaddr).to_s
    end
    def siaddr=(ip)
      @siaddr = IPAddress::IPv4.new(ip).data
    end

    def giaddr
      IPAddress::IPv4::parse_data(@giaddr).to_s
    end
    def giaddr=(ip)
      @giaddr = IPAddress::IPv4.new(ip).data
    end
  end

  ## BOOTP TYPES:
  BOOTREQUEST = 1
  BOOTREPLY   = 2

  ## HARDWARE TYPES: [htype code, hlen length]
  HTYPE = {
    :htype_10mb_ethernet => [ 1, 6 ]
  }

  ## DHCP MESSAGE TYPES:
  DHCPDISCOVER        = 1
  DHCPOFFER           = 2
  DHCPREQUEST         = 3
  DHCPDECLINE         = 4
  DHCPACK             = 5
  DHCPNAK             = 6
  DHCPRELEASE         = 7
  DHCPINFORM          = 8
  DHCPFORCERENEW      = 9 ## RFC 3203
  ##  LEASEQUERY extensions:
  DHCPLEASEQUERY      = 10
  DHCPLEASEUNASSIGNED = 11
  DHCPLEASEUNKNOWN    = 12
  DHCPLEASEACTIVE     = 13

  ## OPTIONS:
  MAGIC   = [99, 130, 83, 99].pack('C4')

  ## Options 0-18 and 254 are defined in RFC 1497 (BOOTP)
  ## TODO: Add in as yet unhandled options
  OPTIONS = {
    :pad                           => [   0, Opt             ],
    :subnet_mask                   => [   1, OptIP           ],
    :time_offset                   => [   2, OptSInt32       ], ## Offset from GMT (signed 32-bit integer seconds)
    :routers                       => [   3, OptIPList       ], ## Default gateway(s)
    :time_servers                  => [   4, OptIPList       ],
    :name_servers                  => [   5, OptIPList       ], ## IEN-116 name servers
    :dns_servers                   => [   6, OptIPList       ], ## DNS server(s) (RFC-1034/1025)
    :log_servers                   => [   7, OptIPList       ], ## Log server(s) (MIT-LCS UDP log servers)
    :cookie_servers                => [   8, OptIPList       ], ## Cookie/Quote-of-the-day (RFC 865) server(s)
    :lpr_servers                   => [   9, OptIPList       ], ## LPR server(s) (RFC 1179)
    :impress_servers               => [  10, OptIPList       ], ## Impress server(s) (in pref. order)
    :rlp_servers                   => [  11, OptIPList       ], ## RLP server(s) (RFC 887)
    :host_name                     => [  12, OptHost         ], ## May or may not be qualified with local domain name (RFC 1035)
    :boot_file_size                => [  13, OptInt16        ], ## Boot file size (number of 512-byte blocks as unsigned 16-bit integer)
    :merit_dump_file               => [  14, OptData         ], ## File name client should dump core to
    :domain_name                   => [  15, OptHost         ], ## RFC 1034/1035 domain name
    :swap_server                   => [  16, OptIP           ], ## Swap server
    :root_path                     => [  17, OptData         ], ## Pathname to mount as root disk
    :extensions_path               => [  18, OptData         ], ## TFTP-available file containing info to be interpreted the same way as 64-byte vendor-extension field in a BOOTP response with some exceptions (See RFC 1497)
    :ip_forwarding                 => [  19, OptBool         ], ## Host should enable/disable IP forwarding (0=disable/1=enable)
    :nonlocal_source_routing       => [  20, OptBool         ], ## Enable/disable source routing
    :interface_mtu                 => [  26, OptInt16        ],
    :broadcast_address             => [  28, OptIP           ],
    :perform_mask_discovery        => [  29, OptBool         ], ## This server always sets to NO/FALSE
    :mask_supplier                 => [  30, OptBool         ], ## This server always sets to NO/FALSE
    :perform_router_discovery      => [  31, OptBool         ], ## This server always sets to NO/FALSE - RFC 1265
    :router_solicitation_address   => [  32, OptIP           ],
    :static_routes                 => [  33, OptStaticRoutes ], ## Use option 121 instead - Must NOT specify default route with this
    :arp_cache_timeout             => [  35, OptInt32        ], ## Unsigned integer no. of seconds for ARP cache timeout
    :ethernet_encapsulation        => [  36, OptBool         ], ## 0/false = Eth. v2 RFC 894 encapsulation, 1/true = 802.3 RFC 1042 encapsulation
    :ntp_servers                   => [  42, OptIPList       ],
    :vendor_specific_information   => [  43, OptSubList      ],
    :netbios_name_server           => [  44, OptIPList       ], ## NetBIOS name server list 
    :netbios_over_tcpip_node_type  => [  46, OptByte         ], ## NetBIOS node type: 1=B-node, 2=P-node, 4=M-node, 8=H-node
    :netbios_over_tcpip_scope      => [  47, OptData         ], ## NetBIOS scope
    :requested_ip_address          => [  50, OptIP           ], ## Client's requested IP
    :ip_address_lease_time         => [  51, OptInt32        ], ## How long the lease lasts
    :option_overload               => [  52, OptByte         ], ## 1, 2, or 3 == 'file' has options, 'sname' has options, both have options
    :dhcp_message_type             => [  53, OptByte         ], ## One of the above-defined DHCP MESSAGE TYPEs
    :server_identifier             => [  54, OptIP           ], ## How the client differentiates between DHCP servers
    :parameter_request_list        => [  55, OptByteList     ], ## List of options the CLIENT is requesting in response
    :message                       => [  56, OptData         ], ## Message in DHCPNAK or DHCPDECLINE saying why that response was sent
    :maximum_dhcp_message_size     => [  57, OptInt16        ], ## Client tells server max. message size it will accept
    :vendor_class_identifier       => [  60, OptData         ], ## MS boxes send "MSFT 98" or "MSFT 5.0"
    :client_identifier             => [  61, OptHexString    ], ## Client's identifier (client picks ANYTHING)
    :smtp_servers                  => [  69, OptIPList       ],
    :tftp_server_name              => [  66, OptData         ], ## TFTP 'sname' value if 'sname' is overloaded with options
    :bootfile_name                 => [  67, OptData         ], ## File name in 'file' if 'file' is overloaded with options
    :pop3_servers                  => [  70, OptIPList       ],
    :client_fqdn                   => [  81, OptData         ], ## Client's requested FQDN (DHCP server could use to update dynamic DNS)
    :relay_agent_information       => [  82, OptSubList      ], ## VERY USEFUL with Cisco CMTS and Motorola Canopy
    :isns_servers                  => [  83, OptData         ], ## RFC 4184 Internet Storage Name Servers DHCP option (primary and backup)
    :authentication                => [  90, OptData         ], ## RFC 3118 authentication option -- NOT IMPLEMENTED
    :client_last_transaction_time  => [  91, OptInt32        ], ## RFC 4388 leasequery option
    :associated_ip                 => [  92, OptIPList       ], ## RFC 4388 leasequery option
    :tz_posix                      => [ 100, OptData         ], ## RFC 4833 timezone TZ-POSIX string (a POSIX time zone string like "MST7MDT6,M3.2.0/02:00,M11.1.0/02:00" which specifies an offset of 7 hours behind UTC during standard time, 6 during daylight time, with daylight beginning the 2nd Sunday in March at 2:00 AM local time and continuing until the 1st Sunday in November at 2:00 AM local time)
    :tz_database                   => [ 101, OptData         ], ## RFC 4833 timezone TZ-Database string (the name of a time zone in a database, like "America/Denver")
    :classless_static_routes       => [ 121, OptRouteList    ], ## RFC 3442 classless static routes - obsoletes option 33 - Ignore opt. 33 if 121 is present - Should specify default routes using option 3 if this option is also present (can specify them in this option too) so if a client ignores 121, a default route will still be set up -- If client requests CLASSLESS STATIC ROUTES and either ROUTERS and/or STATIC ROUTES, ONLY respond with this option (see p. 6 RFC 3442)
    ## START SITE-SPECIFIC OPTIONS (128..254 inclusive):
    :ms_classless_static_routes    => [ 249, OptRouteList    ], ## Microsoft version of option 121 - does NOT ignore opt. 33 if present (differs from opt. 121)
    :site_local_auto_proxy_config  => [ 252, OptData         ], ## WPAD site-local proxy configuration
    ## END SITE-SPECIFIC OPTIONS
    :end                           => [ 255, Opt             ]
  }

  def self.make_opt_name(name, data=nil)
    raise "Unknown/unhandled option '#{name}'" unless OPTIONS.key?(name)
    OPTIONS[name][1].new(OPTIONS[name][0], name, data)
  end

  def self.make_opt(opt, data=nil)
    OPTIONS.each do |name, info|
      return info[1].new(info[0], name, data) if info[0] == opt
    end
    return nil
  end
end

