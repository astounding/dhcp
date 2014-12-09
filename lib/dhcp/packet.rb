#!/usr/bin/env ruby
# encoding: ASCII-8BIT

require_relative 'options'

module DHCP

  ## Class representing a DHCP packet (a request or a response)
  ## for creating said packets, or for parsing them from a UDP
  ## DHCP packet data payload.
  class Packet
    def initialize(opt={})
      data = nil
      if opt.is_a?(String)
        data = opt
        opt = {}
      end
      ## 1: Operation (BOOTREQUEST=1/BOOTREPLY=2)
      @op = opt[:op]
      raise "Invalid/unsupported operation type #{@op}" unless @op.nil? || @op == BOOTREQUEST || @op == BOOTREPLY
      @htype_name = :htype_10mb_ethernet  ## Only supported type currently...
      @htype   = HTYPE[@htype_name][0] ## 1: Hardware address type
      @hlen    = HTYPE[@htype_name][1] ## 1: Hardware address length
      @hops    = 0                     ## 1: Client sets to zero, relays may increment
      @xid     = opt[:xid]   || 0      ## 4: Client picks random 32-bit XID (session ID of sorts)
      @secs    = opt[:secs]  || 0      ## 4: Seconds elapsed since client started transaction
      @flags   = opt[:flats] || 0      ## 2: Leftmost bit is the 'BROADCAST' flag (if set) - Others are zero (reserved for future use)

      ## 4: "Client IP"  -- Only set by client if client state is BOUND/RENEW/REBINDING and client can respond to ARP requests
      @ciaddr = IPAddress::IPv4.new(opt[:ciaddr] || '0.0.0.0').data

      ## 4: "Your IP"    -- Server assigns IP to client
      @yiaddr = IPAddress::IPv4.new(opt[:yiaddr] || '0.0.0.0').data

      ## 4: "Server IP"  -- IP of server to use in NEXT step of client bootstrap process
      @siaddr = IPAddress::IPv4.new(opt[:siaddr] || '0.0.0.0').data

      ## 4: "Gateway IP" -- Relay agent will set this to itself and modify replies
      @giaddr = IPAddress::IPv4.new(opt[:giaddr] || '0.0.0.0').data

      ## 16: Client hardware address (see htype and hlen)
      @chaddr = (opt[:chaddr] || ('00' * @hlen)).gsub(%r{[ :._-]},'').downcase
      raise 'Invalid client hardware address.' unless @chaddr.size == @hlen*2 && %r{\A[a-f0-9]{2}+\Z}.match(@chaddr)
      @chaddr = @chaddr.scan(%r{..}m).map{|b| b.to_i(16).chr}.join

      ## 64: Server host name (optional) as C-style null/zero terminated string (may instead contain options)
      ## If provided by caller, do NOT include the C-style null/zero termination character.
      @sname = opt[:sname] || ''
      raise 'Invalid server host name string.' unless @sname.size < 64

      ## 128: Boot file name (optional) as C-style null/zero terminated string (may instead contain options)
      ## If provided by caller, do NOT include the C-style null/zero termination character.
      @file = opt[:file] || ''
      raise 'Invalid boot file name string.' unless @sname.size < 128

      ## variable: Options - Up to 312 bytes in a 576-byte DHCP message - First four bytes are MAGIC
      @options = ''  ## Preserve any parsed packet's original binary option data - NOT set for non-parsed generated packets
      @optlist = []

      @type      = nil
      @type_name = 'UNKNOWN'
      if opt[:type]
        include_opt(DHCP.make_opt_name(:dhcp_message_type, opt[:type].is_a?(String) ? DHCP::MSG_STR_TO_TYPE[opt[:type]] : opt[:type]))
      end

      ## Default to BOOTREQUEST when generating a blank (invalid) packet:
      @op = BOOTREQUEST if @op.nil?

      ## If a packet was provided, parse it:
      _parse(data) unless data.nil?
    end
    attr_reader :op, :htype_name, :htype, :hlen, :hops, :xid, :secs, :flags, :type, :type_name, :options, :optlist
    attr_accessor :secs, :xid

    ## Both #clone and #dup will call this:
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

    ## It is recommended that when creating a DHCP packet from scratch, use
    ## include_opt(opt) instead so that the "end" option will be correctly
    ## added or moved to the end.  append_opt(opt) will not automatically
    ## add an "end" nor will it move an existing "end" option, possibly
    ## resulting in an invalid DHCP packet if not used carefully.
    def append_opt(opt)
      if opt.name == :dhcp_message_type
        unless @type.nil?
          raise "DHCP message type ALREADY SET in packet"
        end
        set_type(opt)
      end
      @optlist << opt
    end

    def sname
      ## If the option overload is value 2 or 3, look for a :tftp_server_name option:
      opt = get_option(:option_overload)
      return @sname if opt.nil? || opt.get == 1
      opt = get_option(:tftp_server_name)
      return opt.nil? ? '' : opt.get
    end
 
    def sname=(val)
      @sname=val
    end

    def file
      ## If the option overload is value 1 or 3, look for a :bootfile_name option:
      opt = get_option(:option_overload)
      return @file if opt.nil? || opt.get == 2
      opt = get_option(:bootfile_name)
      return opt.nil? ? '' : opt.get
    end

    ## This is the best way to add an option to a DHCP packet:
    def include_opt(opt)
      list     = @optlist
      @options = ''
      @optlist = []
      list.each do |o|
        ## This implementation currently doesn't support duplicate options yet:
        raise "Duplicate option in packet." if o.name == opt.name
        ## Skip/ignore the end option:
        @optlist << o unless o.name == :end
      end
      append_opt(opt)
      @optlist << Opt.new(255, :end)
    end

    def _find_htype(htype)
      HTYPE.each do |name, htype|
        if htype[0] == @htype
          return name
        end
      end
      return nil
    end

    def _parse(msg)
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
      self
    end

    def set_type(opt)
      @type = opt.get
      if DHCP::MSG_TYPE_TO_OP.key?(@type)
        @type_name = DHCP::MSG_TYPE_TO_STR[@type]
        @op = DHCP::MSG_TYPE_TO_OP[@type] if @op.nil?
        raise "Invalid OP #{@op} for #{@type_name}" unless @op == DHCP::MSG_TYPE_TO_OP[@type]
      else
        raise "Invalid or unsupported DHCP MESSAGE TYPE"
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
      packet + (packet.size < 300 ? 0.chr * (300 - packet.size) : '')  ## Pad to minimum of 300 bytes -  Minimum BOOTP/DHCP packet size (RFC 951) - Some devices will drop packets smaller than this.
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

end

