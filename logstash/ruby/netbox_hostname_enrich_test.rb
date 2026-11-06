# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.
# frozen_string_literal: true

require 'json'
require 'minitest/autorun'

class HostnameEnrichment
  class_eval(File.read(File.expand_path('netbox_hostname_enrich.rb', __dir__)))
end

class HostEvent
  def initialize(data)
    @data = data.dup
  end

  def get(key)
    @data[key]
  end

  def set(key, value)
    @data[key] = value
  end
end

class TestHostnameEnrichment < Minitest::Test
  Response = Struct.new(:status, :body)
  Request = Struct.new(:headers, :options)
  Options = Struct.new(:timeout, :open_timeout)

  class FakeClient
    attr_reader :calls

    def initialize(&block)
      @block = block
      @calls = []
    end

    def get(path, query)
      request = Request.new({}, Options.new)
      yield request if block_given?
      @calls << [path, query, request]
      result = @block.call(path, query)
      raise result if result.is_a?(Exception)

      Response.new(200, JSON.generate(result))
    end
  end

  def setup
    @script = HostnameEnrichment.new
    @script.register('enabled' => 'true', 'netbox_enabled' => 'true',
                     'token' => 'fixture-token', 'default_site' => 'Malcolm',
                     'netbox_url' => 'https://example.invalid/netbox')
    @client = build_client
    @script.instance_variable_set(:@client, @client)
  end

  def build_client(device: true, vm: false, site_count: 1, wrong_site: false)
    FakeClient.new do |path, _query|
      case path
      when 'dcim/sites/'
        { 'count' => site_count, 'results' => (
          site_count == 1 ? [{ 'id' => 42, 'name' => 'Malcolm' }] : []
        ) }
      when 'dcim/devices/'
        { 'count' => device ? 1 : 0, 'results' => device ? [
          { 'id' => 123, 'name' => 'workstation.example.org',
            'site' => { 'id' => wrong_site ? 43 : 42 } }
        ] : [] }
      when 'virtualization/virtual-machines/'
        { 'count' => vm ? 1 : 0, 'results' => vm ? [
          { 'id' => 777, 'name' => 'workstation.example.org', 'site' => { 'id' => 42 } }
        ] : [] }
      end
    end
  end

  def event(extra = {})
    HostEvent.new({ '[host][name]' => 'workstation.example.org' }.merge(extra))
  end

  def test_site_scoped_lookup_and_authentication
    data = event('[tags]' => ['security'])
    assert_equal [data], @script.filter(data)
    assert_equal({ 'id' => 123, 'name' => 'workstation.example.org',
                   'site_id' => 42, 'kind' => 'device' }, data.get('[host][netbox]'))
    assert_equal %w[security netbox], data.get('[tags]')
    assert_equal ['dcim/sites/', 'dcim/devices/', 'virtualization/virtual-machines/'],
                 @client.calls.map(&:first)
    assert_equal 42, @client.calls[1][1][:site_id]
    assert_equal 'Token fixture-token', @client.calls[1][2].headers['Authorization']
  end

  def test_numeric_site_skips_site_query
    data = event('[@metadata][nbsiteid]' => 42)
    @script.filter(data)
    assert_equal 2, @client.calls.size
    assert_equal 'device', data.get('[host][netbox]')['kind']
  end

  def test_virtual_machine_match
    @script.instance_variable_set(:@client, build_client(device: false, vm: true))
    data = event
    @script.filter(data)
    assert_equal 'virtual_machine', data.get('[host][netbox]')['kind']
  end

  def test_ambiguous_matches_do_not_enrich
    @script.instance_variable_set(:@client, build_client(vm: true))
    data = event
    @script.filter(data)
    assert_nil data.get('[host][netbox]')
  end

  def test_wrong_site_and_ambiguous_site_are_not_used
    @script.instance_variable_set(:@client, build_client(wrong_site: true))
    data = event
    @script.filter(data)
    assert_nil data.get('[host][netbox]')
    @script.instance_variable_set(:@client, build_client(site_count: 2))
    @script.instance_variable_set(:@cache, {})
    data = event
    @script.filter(data)
    assert_nil data.get('[host][netbox]')
  end

  def test_network_flows_and_site_zero_are_untouched
    [
      event('[source][ip]' => '192.0.2.1'),
      event('[destination][ip]' => '192.0.2.2'),
      event('[@metadata][nbsiteid]' => '0')
    ].each { |data| assert_nil @script.filter(data).first.get('[host][netbox]') }
    assert_empty @client.calls
  end

  def test_invalid_hostname_and_preexisting_match_are_untouched
    [event('[host][name]' => ''), event('[host][name]' => 'invalid name'),
     event('[host][netbox]' => { 'id' => 9 })].each do |data|
      assert_equal [data], @script.filter(data)
    end
    assert_empty @client.calls
  end

  def test_opt_in_and_netbox_flags_are_required
    @script.register('enabled' => 'false', 'netbox_enabled' => 'true',
                     'token' => 'fixture-token')
    @script.filter(event)
    assert_empty @client.calls
    @script.register('enabled' => 'true', 'netbox_enabled' => 'false',
                     'token' => 'fixture-token')
    @script.filter(event)
    assert_empty @client.calls
  end

  def test_site_and_hostname_results_are_cached
    @script.filter(event)
    @script.filter(event)
    assert_equal 3, @client.calls.size
  end

  def test_netbox_outage_keeps_event_intact
    offline = FakeClient.new { |_path, _query| Faraday::ConnectionFailed.new('offline') }
    @script.instance_variable_set(:@client, offline)
    data = event
    assert_equal [data], @script.filter(data)
    assert_nil data.get('[host][netbox]')
  end

  def test_no_matching_inventory_is_left_unenriched
    @script.instance_variable_set(:@client, build_client(device: false))
    data = event('[tags]' => ['syslog'])
    @script.filter(data)
    assert_nil data.get('[host][netbox]')
    assert_equal ['syslog'], data.get('[tags]')
  end

  def test_hostname_trailing_dot_and_case_are_normalized
    data = event('[host][name]' => 'WORKSTATION.EXAMPLE.ORG.')
    @script.filter(data)
    assert_equal 123, data.get('[host][netbox]')['id']
    assert_equal 'WORKSTATION.EXAMPLE.ORG', @client.calls[1][1][:name]
  end

  def test_bad_api_response_is_safe
    malformed = FakeClient.new { |_path, _query| { 'error' => 'bad result' } }
    @script.instance_variable_set(:@client, malformed)
    data = event
    assert_equal [data], @script.filter(data)
    assert_nil data.get('[host][netbox]')
  end

  def test_site_with_multiple_results_is_never_matched
    duplicate = FakeClient.new do |path, _query|
      if path == 'dcim/sites/'
        { 'count' => 2, 'results' => [
          { 'id' => 42, 'name' => 'Malcolm' },
          { 'id' => 43, 'name' => 'Malcolm' }
        ] }
      end
    end
    @script.instance_variable_set(:@client, duplicate)
    data = event
    @script.filter(data)
    assert_nil data.get('[host][netbox]')
    assert_equal ['dcim/sites/'], duplicate.calls.map(&:first)
  end

  def test_pipeline_wiring_is_opt_in
    conf = File.read(File.expand_path('../pipelines/enrichment/21_netbox.conf', __dir__))
    assert_includes conf, 'netbox_hostname_enrich.rb'
    assert_includes conf, '${LOGSTASH_NETBOX_ENRICH_HOSTNAMES:false}'
    assert_includes conf, '${NETBOX_ENRICHMENT:false}'
    assert_includes conf, '![source][ip]'
    assert_includes conf, '![destination][ip]'
  end
end
