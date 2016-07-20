#!/usr/bin/env ruby

require 'ipaddr'
require 'pcaprub'

# https://en.wikipedia.org/wiki/EtherType
ETHER_TYPE = {
  0x0800 => :ipv4,
  0x0806 => :arp
}

module DataConverters
  def mac_address(byte_str)
    byte_str.unpack('C6').map { |s| sprintf('%02x', s) }.join(':')
  end

  def int8(byte_str)
    byte_str.unpack('C')[0]
  end

  def int16(byte_str)
    byte_str.unpack('n')[0]
  end

  def int32(byte_str)
    byte_str.unpack('N')[0]
  end

  def ipv4_addr(byte_str)
    IPAddr.new(int32(byte_str), Socket::AF_INET)
  end
end

class EthernetFrame
  extend DataConverters

  attr_reader :fields

  def self.parse(raw_byte_str)
    raw_byte_str.force_encoding(Encoding::BINARY)

    # The first 8 bytes 'preamble' and 'start of frame delimiter' seem to not
    # be present when we use libpcap. At this point we've also had the frame
    # check sequence stripped off and the packet may not have had padding added
    # to it. That makes this a slightly modified 'layer 2 ethernet frame'. We
    # can only really tell if we have all the headers we need by length + at
    # least 1 for payload, so we mind as well check that...
    unless raw_byte_str.length >= 15
      fail(ArgumentError, 'Not enough bytes to be an ethernet frame.')
    end

    fields = {
      mac_dest: mac_address(raw_byte_str[0,6]),
      mac_src: mac_address(raw_byte_str[6,6])
    }

    # VLAN tag information is 4 bytes that exist between the src_destination
    # and ethertype fields but is only present when a tag is set. This is
    # indicated with the special value 0x8100 where the ether_type field
    # normally is.
    if int16(raw_byte_str[12,2]) == 0x8100
      fields[:vlan_tag] = int32(raw_byte_str[12,4])
      fields[:ether_type] = int16(raw_byte_str[16,2])
      fields[:payload] = raw_byte_str[17..-1]
    else
      fields[:ether_type] = int16(raw_byte_str[12,2])
      fields[:payload] = raw_byte_str[14..-1]
    end

    new(fields)
  end

  def payload
    return @payload if @payload

    if fields[:ether_type] <= 1500
      # Only indicates payload *size*, we'd need to do sub-protocol detection
      # ourselves. I believe payload extraction is handled within libpcap
      # though it appears to leave padding in.
      if fields[:ether_type] != fields[:payload].length
        warn('Ethernet frame payload length mismatch (%i/%i).' % [fields[:ether_type], fields[:payload].length])
      end
    end

    # Check if this is an ARP packet
    case fields[:ether_type]
    when 0x0800
      # IPv4
    when 0x0806
      # ARP
      @payload = ARPPacket.parse(fields[:payload], self)
    when 0x8137
      # IPX
    when 0x86dd
      # IPv6
    else
      # Unknown
      @payload = fields[:payload]
    end
  end

  def initialize(fields = {})
    @fields = fields
  end
end

class ARPPacket
  extend DataConverters

  attr_reader :fields

  def self.parse(raw_byte_str, parent = nil)
    raw_byte_str.force_encoding(Encoding::BINARY)

    unless raw_byte_str.length >= 28
      warn('Incorrect byte length (%i) for an ARP packet' % raw_byte_str.length)
    end

    fields = {
      hardware_type:      int16(raw_byte_str[0,2]),
      protocol_type:      int16(raw_byte_str[2,2]),
      hardware_len:       int8(raw_byte_str[4]),
      protocol_len:       int8(raw_byte_str[5]),
      operation:          int16(raw_byte_str[6,2])
    }

    # This is where the packet disection gets a little weird... We need to use
    # a value we've already retrieved to build up the rest of the information.
    # Man there has GOT to be a better way to do this... Maybe using a string
    # scanner?
    offset = 8
    fields[:sender_hw_addr] = raw_byte_str[offset, fields[:hardware_len]]
    offset += fields[:hardware_len]
    fields[:sender_proto_addr] = raw_byte_str[offset, fields[:protocol_len]]
    offset += fields[:protocol_len]
    fields[:target_hw_addr] = raw_byte_str[offset, fields[:hardware_len]]
    offset += fields[:hardware_len]
    fields[:target_proto_addr] = raw_byte_str[offset, fields[:protocol_len]]

    offset += fields[:protocol_len]

    # Funny thing...
    unless raw_byte_str.length == offset || raw_byte_str[offset..-1].bytes.select { |b| b != 0x00 }.empty?
      warn('Additional hidden data found in ARP packet: %s' % raw_byte_str[offset..-1].inspect)
    end

    new(fields)
  end

  def hardware_type
    return :ethernet if fields[:hardware_type] == 1
    fields[:hardware_type]
  end

  def initialize(fields = {}, parent = nil)
    @fields = fields
    @parent = parent
  end

  # @return [:announcement, :gratuitous, :invalid, :probe, :request, :response]
  def operation
    return :announcement if fields[:target_proto_addr] == fields[:sender_proto_addr] && fields[:target_hw_addr] == fields[:sender_hw_addr]
    return :gratuitous if fields[:target_proto_addr] == fields[:sensor_proto_addr] && fields[:target_hw_addr] == '00:00:00:00:00:00'

    if fields[:operation] == 1
      return :probe if fields[:target_proto_addr] == '0.0.0.0'
      return :request
    end

    return :reply if fields[:operation] == 2
    return :invalid
  end

  def output
    {
      hardware_type: hardware_type,
      protocol_type: protocol_type,
      operation: operation,
      sender_hw_addr: sender_hw_addr,
      sender_proto_addr: sender_proto_addr,
      target_hw_addr: target_hw_addr,
      target_proto_addr: target_proto_addr
    }
  end

  def protocol_type
    ETHER_TYPE[fields[:protocol_type]] || fields[:protocol_type]
  end

  def sender_hw_addr
    return self.class.mac_address(fields[:sender_hw_addr]) if hardware_type == :ethernet
    fields[:sender_hw_addr]
  end

  def sender_proto_addr
    return self.class.ipv4_addr(fields[:sender_proto_addr]) if protocol_type == :ipv4
    fields[:sender_proto_addr]
  end

  def target_hw_addr
    return self.class.mac_address(fields[:target_hw_addr]) if hardware_type == :ethernet
    fields[:target_hw_addr]
  end

  def target_proto_addr
    return self.class.ipv4_addr(fields[:target_proto_addr]) if protocol_type == :ipv4
    fields[:target_proto_addr]
  end
end

