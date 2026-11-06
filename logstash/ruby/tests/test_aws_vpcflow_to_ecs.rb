# Unit tests for the Logstash AWS VPC Flow Log ECS normalization filter.
require 'minitest/autorun'
require_relative '../aws_vpcflow_to_ecs'

class TestEvent
  attr_reader :fields

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

class AwsVpcFlowLogToEcsTest < Minitest::Test
  def test_standard_fields_and_original_record
    payload = {
      '[event][module]' => 'aws_vpcflow',
      '[miscbeat][srcaddr]' => '192.0.2.4',
      '[miscbeat][dstaddr]' => '198.51.100.8',
      '[miscbeat][srcport]' => 0,
      '[miscbeat][dstport]' => 443,
      '[miscbeat][bytes]' => 200,
      '[miscbeat][packets]' => 2,
      '[miscbeat][protocol]' => 6,
      '[miscbeat][account_id]' => '000012345678',
      '[miscbeat][region]' => 'eu-west-2',
      '[miscbeat][action]' => 'ACCEPT',
      '[miscbeat][raw]' => '2 000012345678 ... ACCEPT OK',
      '[miscbeat][vendor_field]' => 'kept'
    }
    event = TestEvent.new(payload)
    assert_equal [event], filter(event)
    {
      '[source][ip]' => '192.0.2.4',
      '[destination][ip]' => '198.51.100.8',
      '[source][port]' => 0,
      '[destination][port]' => 443,
      '[network][bytes]' => 200,
      '[network][packets]' => 2,
      '[network][transport]' => 'tcp',
      '[cloud][account][id]' => '000012345678',
      '[cloud][provider]' => 'aws',
      '[cloud][region]' => 'eu-west-2',
      '[event][provider]' => 'aws',
      '[event][dataset]' => 'aws.vpcflow',
      '[event][original]' => '2 000012345678 ... ACCEPT OK',
      '[event][action]' => 'ACCEPT',
      '[event][category]' => ['network']
    }.each do |field, expected|
      assert_equal expected, event.get(field), field
    end
    assert_equal 'kept', event.get('[miscbeat][vendor_field]')
  end

  def test_other_modules_are_untouched
    event = TestEvent.new('[event][module]' => 'cpu')
    assert_equal [event], filter(event)
    assert_equal({'[event][module]' => 'cpu'}, event.fields)
  end

  def test_missing_fields_and_nodata
    event = TestEvent.new('[event][module]' => 'aws_vpcflow',
                          '[miscbeat][log_status]' => 'NODATA',
                          '[miscbeat][raw]' => '2 123 ... NODATA')
    filter(event)
    assert_nil event.get('[source][ip]')
    assert_equal 'aws.vpcflow', event.get('[event][dataset]')
    assert_equal 'NODATA', event.get('[miscbeat][log_status]')
  end

  def test_unknown_protocol_and_udp
    event = TestEvent.new('[event][module]' => 'aws_vpcflow',
                          '[miscbeat][protocol]' => 132)
    filter(event)
    assert_equal '132', event.get('[network][transport]')
    event = TestEvent.new('[event][module]' => 'aws_vpcflow',
                          '[miscbeat][protocol]' => 17)
    filter(event)
    assert_equal 'udp', event.get('[network][transport]')
  end
end
