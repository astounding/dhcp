#!/usr/bin/env ruby
# encoding: ASCII-8BIT
#
# --
#
# Ruby DHCP module for parsing and creating IPv4 DHCP options
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

## Import DHCP module constants:
require_relative 'dhcp'

module DHCP
  ## Base class from which all DHCP options in a DHCP packet derive:
  class Opt
    def initialize(opt, name, ignore=nil)
      @opt  = opt
      @name = name
    end
    attr_reader :opt, :name

    def opt_header
      "OPTION[#{opt},#{@name}]"
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
    @item_size = 0 ## Override this in subclasses
    class << self
      attr_accessor :item_size
    end

    def split_data(data)
      raise "Child class #{self.class} MUST override class item_size variable with non-zero value!" if self.class.item_size == 0
      raise "Invalid data length #{data.size} (expected even multiple of #{self.class.item_size})" unless data.size % self.class.item_size == 0
      list = []
      data = data.dup
      while data.size > 0
        list << bin_to_data(data.slice!(0,self.class.item_size))
      end
      list
    end

    def data_to_bin(item)  ## Override in child, but call super(item)
                           ## with the resulting translated data after
                           ## data translation so the size check is
                           ## applied (or do a size check in the child):
      raise "Invalid data item length #{item.size} (expected #{self.class.item_size})" unless item.size == self.class.item_size
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
    @item_size = 4

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
    @item_size = 8

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
  ## Also acts as parent class for fixed-sized multi-byte value
  ## DHCP options
  class OptInt8 < OptFixedData
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
  class OptInt16 < OptInt8
    @size = 2
  end

  ## Class for four-byte unsigned integer value DHCP options
  class OptInt32 < OptInt8
    @size = 4
  end

  ## Class for four-byte signed integer value DHCP options
  class OptSInt32 < OptInt32
    @size = 4
    ## Convert signed data to unsigned form
    def data_to_bin(data)
      super(data % 2**32)
    end

    ## Convert unsigned form back to signed data
    def bin_to_data(data)
      (super(data) + 2**31) % 2**32 - 2**31
    end
  end

  ## Class for DHCP options containing a list of 8-bit integers (like
  ## lists of requested DHCP options). Also acts as parent class to
  ## lists of larger fixed-sized numeric types.
  class OptInt8List < OptListFixedData
    @item_size = 1

    def bin_to_data(data)
      data.each_byte.inject(0){|sum,byte| sum<<8|byte}
    end

    def data_to_bin(data)
      raise "Invalid numeric data" unless data.is_a?(Fixnum) && data >= 0
      raise "Invalid number" unless data == data & ([0xff] * self.class.item_size).inject(0){|sum,byte| sum<<8|byte}
      bytes = ''
      while data != 0
        bytes = (data & 0xff).chr + bytes
        data >>= 8
      end
      raise "Impossible: Numeric byte size #{bytes.size} exceeds #{self.class.item_size}" if bytes.size > self.class.item_size
      0.chr * (self.class.item_size - bytes.size) + bytes
    end

    def to_s
      opt_header + '=[' + map{|x| x.to_s}.join(',') + ']'
    end
  end

  ## Class for DHCP options containing a list of 16-bit unsigned integers:
  class OptInt16List < OptInt8List
    @item_size = 2
  end

  ## Class for DHCP options containing data that is most often displayed as a string of hexadecimal digit pairs joined by colons (i.e. ethernet MAC addresses)
  class OptHexString < OptData
    def data_to_bin(data)
      data = data.gsub(/[ \.:_\-]/,'')    ## Allow various octet separator characters (trim them out)
      ['0' * (data.size % 2)].pack('H*')  ## Pad hex string to even multiple and translate to binary
    end

    def bin_to_data(data)
      data.each_byte.map{|b| "%0.2X" % [b]}.join(':')  ## Convert each byte to hex string and join bytes with ':'
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

  ## Options 0-18 and 254 are defined in RFC 1497 (BOOTP)
  ## TODO: Add in as yet unhandled options
  OPTIONS = {
    :pad                           => [   0, Opt             ], ## Pad (RFC 2132) - Padding option
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
    :max_dgram_reassembly_size     => [  22, OptInt16        ], ## Maximum Datagram Reassembly Size (RFC 1533) - Min. value 576
    :default_ttl                   => [  23, OptInt8         ], ## Default IP Time-to-live (TTL) (RFC 1533) - Value in the range 1..255 inclusive
    :path_mtu_aging_timeout        => [  24, OptInt32        ], ## Path MTU Aging Timeout Option (RFC 2132) - Timeout to use when aging Path MTU values discovered according to RFC 1191
    :path_mtu_plateau_table        => [  25, OptInt16List    ], ## Path MTU Plateau Table Option (RFC 2132) - List of 16-bit unsigned integers ordered smallest to largest, minimum MTU value NOT smaller than 68, minimum of at least one list entry
    :interface_mtu                 => [  26, OptInt16        ], ## Interface MTU (RFC 1533) - Minimum value 68
    :all_subnets_are_local         => [  27, OptBool         ], ## All Subnets Are Local (RFC 1533) - 0 = client should assume some subnets of directly connected net(s) may have smaller MTUs, 1 = all subnets share single MTU value
    :broadcast_address             => [  28, OptIP           ], ## Broadcast Address (RFC 1533) - Client's broadcast IP on client's subnet
    :perform_mask_discovery        => [  29, OptBool         ], ## Perform Mask Discovery (RFC 1533) - 0 = client should perform mask discovery, 1 = client should not
    :mask_supplier                 => [  30, OptBool         ], ## Mask Supplier (RFC 1533) - 0 = client should NOT respond to subnet mask requests using ICMP, 1 = client should respond
    :perform_router_discovery      => [  31, OptBool         ], ## Perform Router Discover (RFC 1265) - 0 = client should NOT perform router discovery, 1 = client should
    :router_solicitation_address   => [  32, OptIP           ], ## Router Solicitaion Address (RFC 1533) - IP address to which client transmits router solicitation requests
    :static_routes                 => [  33, OptStaticRoutes ], ## Static Route (RFC 15333) - List of static routes client should install in routing cache, listed in descending order of priority (if multiple routes to same dest. are specified) - Use option 121 instead - Must NOT specify default route with this! (Illegal destination '0.0.0.0' for this option.)
    :arp_cache_timeout             => [  35, OptInt32        ], ## ARP Cache Timeout (RFC 1533) - Unsigned 32-bit integer timeout in seconds for ARP cache entries
    :ethernet_encapsulation        => [  36, OptBool         ], ## Ethernet Encapsulation (RFC 1533) - = 0 = use ethernet v2 RFC 894 encapsulation, 1 = use 802.3 RFC 1042 encapsulation
    :tcp_default_ttl               => [  37, OptInt8         ], ## TCP Default TTL (RFC 1533) - Minimum value of 1
    :tcp_keepalive_interval        => [  38, OptInt32        ], ## TCP Keepalive Interval (RFC 1533) - 0 = client should not generate keepalive messages unless requested by application - No. of seconds client should wait before sending keepalive messages on TCP connections
    :ntp_servers                   => [  42, OptIPList       ],
    :vendor_specific_information   => [  43, OptSubList      ],
    :netbios_name_server           => [  44, OptIPList       ], ## NetBIOS name server list 
    :netbios_over_tcpip_node_type  => [  46, OptInt8         ], ## NetBIOS node type: 1=B-node, 2=P-node, 4=M-node, 8=H-node
    :netbios_over_tcpip_scope      => [  47, OptData         ], ## NetBIOS scope
    :requested_ip_address          => [  50, OptIP           ], ## Client's requested IP
    :ip_address_lease_time         => [  51, OptInt32        ], ## How long the lease lasts
    :option_overload               => [  52, OptInt8         ], ## Option Overload (RFC 2132) - 1, 2, or 3 == 'file' has options, 'sname' has options, both have options (RFC 2132)
    :dhcp_message_type             => [  53, OptInt8         ], ## One of the above-defined DHCP MESSAGE TYPEs
    :server_identifier             => [  54, OptIP           ], ## How the client differentiates between DHCP servers
    :parameter_request_list        => [  55, OptInt8List     ], ## List of options the CLIENT is requesting in response
    :message                       => [  56, OptData         ], ## Message in DHCPNAK or DHCPDECLINE saying why that response was sent
    :maximum_dhcp_message_size     => [  57, OptInt16        ], ## Maximum DHCP Message Size (RFD 2132) - Client tells server max. message size it will accept. Minimum allowed value is 576 octets. Do NOT include in DHCPDECLINE messages. On an ethernet with a 1500-byte MTU, subtracting 20 bytes for IP overhead and 8 for UDP overhead, the maximum packet size to use would be 1472 bytes.
    :vendor_class_identifier       => [  60, OptData         ], ## For example, some MS boxes send "MSFT 98" or "MSFT 5.0"
    :client_identifier             => [  61, OptHexString    ], ## Client's identifier (client picks ANYTHING)
    :netware_ip_domain_name        => [  62, OptData         ], ## NetWare/IP Domain Name (RFC 2242)
    :netware_ip_information        => [  63, OptSubList      ], ## NetWare/IP Information (RFC 2242)
    :nis_domain_name               => [  64, OptData         ], ## Network Information Service+ Domain (RFC 2132)
    :nis_servers                   => [  65, OptIPList       ], ## Network Information Service+ Servers (RFC 2132) (one or more IPs)
    :tftp_server_name              => [  66, OptData         ], ## TFTP Server Name (RFC 2132) - Used when the 'sname' field has been used for DHCP options (option 52 has value of 2 or 3)
    :bootfile_name                 => [  67, OptData         ], ## Bootfile Name (RFC 2132) - Used when the 'file' field has been used for DHCP options (option 52 has value of 1 or 3)
    :mobile_ip_home_agent          => [  68, OptIPList       ], ## Mobile IP Home Agent (RFC 2132) list of IP addresses indicating mobile IP home agents available to the client in order of preference (zero or more IPs)
    :smtp_servers                  => [  69, OptIPList       ],
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

    :end                           => [ 255, Opt             ]  ## End (RFC 2132) Mark end of options in vendor field - subsequent bytes are pad options
  }

  ## Create a new DHCP option object based on the symbolic name:
  def self.make_opt_name(name, data=nil)
    raise "Unknown/unhandled option '#{name}'" unless OPTIONS.key?(name)
    OPTIONS[name][1].new(OPTIONS[name][0], name, data)
  end

  ## Create a new DHCP option object based on the option number:
  def self.make_opt(opt, data=nil)
    OPTIONS.each do |name, info|
      return info[1].new(info[0], name, data) if info[0] == opt
    end
    return nil
  end

end

