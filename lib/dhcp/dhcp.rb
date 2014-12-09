#!/usr/bin/env ruby
# encoding: ASCII-8BIT

## http://github.org/bluemonk/ipaddress - A very nice IP address utility gem
require 'ipaddress'

module DHCP

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

  ## Map message type string to integer type:
  MSG_STR_TO_TYPE = {
    'DHCPDISCOVER'        => DHCPDISCOVER,
    'DHCPOFFER'           => DHCPOFFER,
    'DHCPREQUEST'         => DHCPREQUEST,
    'DHCPDECLINE'         => DHCPDECLINE,
    'DHCPACK'             => DHCPACK,
    'DHCPNAK'             => DHCPNAK,
    'DHCPRELEASE'         => DHCPRELEASE,
    'DHCPINFORM'          => DHCPINFORM,
    'DHCPFORCERENEW'      => DHCPFORCERENEW,
    'DHCPLEASEQUERY'      => DHCPLEASEQUERY,
    'DHCPLEASEUNASSIGNED' => DHCPLEASEUNASSIGNED,
    'DHCPLEASEUNKNOWN'    => DHCPLEASEUNKNOWN,
    'DHCPLEASEACTIVE'     => DHCPLEASEACTIVE
  }

  ## Map message integer type to string:
  MSG_TYPE_TO_STR = MSG_STR_TO_TYPE.invert

  ## Map message type to correct packet operation (BOOTREQUEST/BOOTREPLY):
  MSG_TYPE_TO_OP  =  {
    DHCPDISCOVER        => BOOTREQUEST,
    DHCPOFFER           => BOOTREPLY,
    DHCPREQUEST         => BOOTREQUEST,
    DHCPDECLINE         => BOOTREPLY,
    DHCPACK             => BOOTREPLY,
    DHCPNAK             => BOOTREPLY,
    DHCPRELEASE         => BOOTREQUEST,
    DHCPINFORM          => BOOTREQUEST,
    DHCPFORCERENEW      => BOOTREPLY,
    DHCPLEASEQUERY      => BOOTREQUEST,
    DHCPLEASEUNASSIGNED => BOOTREPLY,
    DHCPLEASEUNKNOWN    => BOOTREPLY,
    DHCPLEASEACTIVE     => BOOTREPLY
  }

  ## DHCP MAGIC:
  MAGIC   = [99, 130, 83, 99].pack('C4')

end

