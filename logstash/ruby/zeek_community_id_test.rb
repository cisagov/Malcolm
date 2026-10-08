#!/usr/bin/env ruby
# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.
# frozen_string_literal: true

require 'minitest/autorun'

class ZeekCommunityIdFilter
  class_eval(File.read(File.join(__dir__, 'zeek_community_id.rb')), File.join(__dir__, 'zeek_community_id.rb'))
end

class SyntheticFlow
  def initialize(fields)
    @fields = fields
  end

  def get(field)
    @fields[field]
  end

  def set(field, value)
    @fields[field] = value
  end
end

class ZeekCommunityIdTest < Minitest::Test
  def setup
    @script = ZeekCommunityIdFilter.new
    @script.register('enabled' => 'true')
  end

  def flow(source_ip: '10.0.0.1', destination_ip: '10.0.0.2', source_port: 10,
           destination_port: 20, transport: 'tcp', community_id: nil)
    SyntheticFlow.new(
      '[source][ip]' => source_ip,
      '[destination][ip]' => destination_ip,
      '[source][port]' => source_port,
      '[destination][port]' => destination_port,
      '[network][transport]' => transport,
      '[network][community_id]' => community_id
    )
  end

  def id(event)
    assert_equal [event], @script.filter(event)
    event.get('[network][community_id]')
  end

  def test_tcp_reference_vector
    assert_equal '1:9j2Dzwrw7T9E+IZi4b4IVT66HBI=', id(flow)
  end

  def test_reverse_direction_has_same_community_id
    reversed = flow(source_ip: '10.0.0.2', destination_ip: '10.0.0.1',
                    source_port: 20, destination_port: 10)
    assert_equal id(flow), id(reversed)
  end

  def test_udp_reference_vector
    example = flow(source_ip: '192.0.2.5', destination_ip: '198.51.100.10',
                   source_port: '53000', destination_port: '53', transport: 'udp')
    assert_equal '1:DPVOOGXtHx+Q5omQmVCaTZHRIwM=', id(example)
  end

  def test_ipv6_reference_vector
    example = flow(source_ip: '2001:db8::1', destination_ip: '2001:db8::2',
                   source_port: 44321, destination_port: 443)
    assert_equal '1:sxEdrRqLnmErfojaOh3beVONlNs=', id(example)
  end

  def test_sctp_reference_vector
    example = flow(source_ip: '10.10.0.1', destination_ip: '10.10.0.2',
                   source_port: 5000, destination_port: 5001, transport: 'sctp')
    assert_equal '1:M7CUIuS3FcIac8i27qXOBB2RX8E=', id(example)
  end

  def test_ascii_zeek_singleton_transport_and_ports
    example = flow(transport: ['tcp'], source_port: ['10'], destination_port: ['20'])
    assert_equal '1:9j2Dzwrw7T9E+IZi4b4IVT66HBI=', id(example)
  end

  def test_preserves_existing_community_id
    assert_equal '1:existing', id(flow(community_id: '1:existing'))
  end

  def test_disabled_does_not_add_id
    @script.register('enabled' => 'false')
    assert_nil id(flow)
  end

  def test_unsupported_and_incomplete_tuples
    assert_nil id(flow(transport: 'icmp'))
    assert_nil id(flow(transport: ['tcp', 'udp']))
    assert_nil id(flow(source_ip: nil))
    assert_nil id(flow(destination_port: nil))
    assert_nil id(flow(source_ip: 'not-an-ip'))
    assert_nil id(flow(source_ip: '10.0.0.0/8'))
    assert_nil id(flow(destination_ip: '2001:db8::1'))
    assert_nil id(flow(source_port: '-'))
    assert_nil id(flow(source_port: -1))
    assert_nil id(flow(destination_port: 65_536))
  end

  def test_same_address_orders_ports
    a = flow(source_ip: '127.0.0.1', destination_ip: '127.0.0.1',
             source_port: 1234, destination_port: 80)
    b = flow(source_ip: '127.0.0.1', destination_ip: '127.0.0.1',
             source_port: 80, destination_port: 1234)
    assert_equal id(a), id(b)
  end
end
