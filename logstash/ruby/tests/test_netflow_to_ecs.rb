# Unit tests for Logstash netflow_to_ecs.rb; no Logstash runtime needed.
require 'minitest/autorun'
require 'json'
require_relative '../netflow_to_ecs'

class TestEvent
  attr_reader :fields

  def initialize(payload)
    @fields = {'[netflow]' => payload}
  end

  def get(key)
    @fields[key]
  end

  def set(key, value)
    @fields[key] = value
  end
end

class NetflowToEcsTest < Minitest::Test
  def test_standard_fields_and_event_metadata
    payload = {
      'ipv4_src_addr' => '192.0.2.10',
      'ipv4_dst_addr' => '198.51.100.20',
      'l4_src_port' => 443,
      'l4_dst_port' => 52235,
      'in_bytes' => 0,
      'in_pkts' => 13,
      'protocol' => 6,
      'vendor_record' => 'preserved'
    }
    event = TestEvent.new(payload)
    assert_equal [event], filter(event)
    expected = {
      '[source][ip]' => '192.0.2.10',
      '[destination][ip]' => '198.51.100.20',
      '[source][port]' => 443,
      '[destination][port]' => 52235,
      '[network][bytes]' => 0,
      '[network][packets]' => 13,
      '[network][transport]' => 'tcp',
      '[event][module]' => 'netflow',
      '[event][dataset]' => 'netflow.v9',
      '[event][kind]' => 'event',
      '[event][category]' => ['network'],
      '[event][type]' => ['info']
    }
    expected.each do |key, value|
      assert_equal value, event.get(key), key
    end
    assert_equal payload, JSON.parse(event.get('[event][original]'))
    assert_equal 'preserved', event.get('[netflow]')['vendor_record']
  end

  def test_unknown_protocol_and_absent_fields
    event = TestEvent.new('protocol' => 132)
    assert_equal [event], filter(event)
    assert_equal '132', event.get('[network][transport]')
    refute event.fields.key?('[source][ip]')
    refute event.fields.key?('[network][packets]')
  end

  def test_handles_udp_and_icmp
    {1 => 'icmp', 17 => 'udp', 58 => 'icmpv6'}.each do |num, name|
      event = TestEvent.new('protocol' => num.to_s)
      filter(event)
      assert_equal name, event.get('[network][transport]')
    end
  end

  def test_empty_record
    event = TestEvent.new({})
    assert_equal [event], filter(event)
    assert_equal '{}', event.get('[event][original]')
  end

  def test_undecodable_data_is_dropped
    event = TestEvent.new(nil)
    assert_equal [], filter(event)
    event = TestEvent.new('not a decoded hash')
    assert_equal [], filter(event)
  end
end
