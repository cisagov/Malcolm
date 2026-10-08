# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.
# frozen_string_literal: true

require 'base64'
require 'digest'
require 'ipaddr'

# Computes Community ID v1 for flow-oriented Zeek events with a complete
# TCP, UDP or SCTP tuple. Other protocols are left unchanged.
def register(params)
  @enabled = %w[true yes on 1].include?(params.fetch('enabled', 'false').to_s.downcase)
end

def filter(event)
  return [event] unless @enabled
  return [event] unless event.get('[network][community_id]').nil?

  transport = event.get('[network][transport]')
  transport = transport.first if transport.is_a?(Array) && transport.size == 1
  protocol = case transport.to_s.downcase
             when 'tcp' then 6
             when 'udp' then 17
             when 'sctp' then 132
             end
  return [event] if protocol.nil?

  source_ip = event.get('[source][ip]')
  destination_ip = event.get('[destination][ip]')
  return [event] unless source_ip.is_a?(String) && destination_ip.is_a?(String)
  return [event] if source_ip.include?('/') || destination_ip.include?('/')

  source = IPAddr.new(source_ip)
  destination = IPAddr.new(destination_ip)
  return [event] unless source.ipv4? == destination.ipv4?

  source_port = community_id_port(event.get('[source][port]'))
  destination_port = community_id_port(event.get('[destination][port]'))
  return [event] if source_port.nil? || destination_port.nil?

  source_bytes = source.hton
  destination_bytes = destination.hton
  order = source_bytes <=> destination_bytes
  if order.positive? || (order.zero? && source_port > destination_port)
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
