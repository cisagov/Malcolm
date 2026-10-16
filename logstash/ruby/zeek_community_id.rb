# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.
# frozen_string_literal: true

require 'base64'
require 'digest'
require 'ipaddr'

# Computes Community ID v1 for flow-oriented Zeek events with a complete
# TCP, UDP, SCTP or ICMP type/code tuple. Other protocols are left unchanged.
# The transport
# comes from [network][transport], or from [@metadata][inferred_transport]
# when the log has no proto column.
def filter(event)
  return [event] unless event.get('[network][community_id]').nil?

  # Prefer the transport Zeek logged; otherwise fall back to the one looked up
  # by log type in 1250_zeek_community_id.conf (see zeek_log_transport.yaml).
  transport = event.get('[network][transport]')
  transport = event.get('[@metadata][inferred_transport]') if transport.nil? || transport == []
  transport = transport.first if transport.is_a?(Array) && transport.size == 1
  source_ip = event.get('[source][ip]')
  destination_ip = event.get('[destination][ip]')
  return [event] unless source_ip.is_a?(String) && destination_ip.is_a?(String)
  return [event] if source_ip.include?('/') || destination_ip.include?('/')

  source = IPAddr.new(source_ip)
  destination = IPAddr.new(destination_ip)
  return [event] unless source.ipv4? == destination.ipv4?

  protocol = community_id_protocol(transport.to_s.downcase, source.ipv4?)
  return [event] if protocol.nil?

  source_port = community_id_port(event.get('[source][port]'))
  destination_port = community_id_port(event.get('[destination][port]'))
  return [event] if source_port.nil? || destination_port.nil?

  # In Zeek conn.log, the two port fields represent ICMP type and code.
  # Paired request/reply types must map to equivalent port pairs for a
  # direction-independent ID. Other ICMP types are one-way, so their source
  # and destination IPs must not be swapped (per the Community ID spec).
  one_way = false
  if protocol == 1 || protocol == 58
    return [event] if source_port > 255 || destination_port > 255

    mapped_type = community_id_icmp_counter_type(protocol, source_port)
    unless mapped_type.nil?
      destination_port = mapped_type
    else
      one_way = true
    end
  end

  source_bytes = source.hton
  destination_bytes = destination.hton
  order = source_bytes <=> destination_bytes
  if !one_way && (order.positive? || (order.zero? && source_port > destination_port))
    source_bytes, destination_bytes = destination_bytes, source_bytes
    source_port, destination_port = destination_port, source_port
  end

  # Seed (16-bit, zero), ordered addresses, protocol + padding, ports.
  binary_flow = [0].pack('n') + source_bytes + destination_bytes +
                [protocol, 0, source_port, destination_port].pack('CCnn')
  digest = Base64.strict_encode64(Digest::SHA1.digest(binary_flow))
  event.set('[network][community_id]', "1:#{digest}")
  [event]
rescue IPAddr::InvalidAddressError, ArgumentError, TypeError
  # Incomplete or malformed Zeek records must not disrupt ingestion.
  [event]
end

def community_id_port(value)
  value = value.first if value.is_a?(Array) && value.size == 1
  return nil unless value.is_a?(Integer) || (value.is_a?(String) && value.match?(/\A\d+\z/))

  port = value.to_i
  port if (0..65_535).cover?(port)
end

# Zeek and Corelight's Community ID protocol handling use these counter-type
# pairs for bidirectional ICMP flows; other ICMP messages remain directional.
ICMP_COUNTER_TYPES = {
  1 => { 0 => 8, 8 => 0, 9 => 10, 10 => 9, 13 => 14, 14 => 13,
         15 => 16, 16 => 15, 17 => 18, 18 => 17 },
  58 => { 128 => 129, 129 => 128, 130 => 131, 131 => 130,
          133 => 134, 134 => 133, 135 => 136, 136 => 135,
          139 => 140, 140 => 139, 144 => 145, 145 => 144 }
}.freeze

def community_id_icmp_counter_type(protocol, message_type)
  ICMP_COUNTER_TYPES.fetch(protocol, {})[message_type]
end

def community_id_protocol(transport, ipv4)
  case transport
  when 'tcp' then 6
  when 'udp' then 17
  when 'sctp' then 132
  when 'icmp' then ipv4 ? 1 : 58
  when 'icmp4', 'icmpv4' then 1 if ipv4
  when 'icmp6', 'icmpv6' then 58 unless ipv4
  end
end
