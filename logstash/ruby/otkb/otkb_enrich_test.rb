#!/usr/bin/env ruby
# frozen_string_literal: true

# Self-contained behavior tests for otkb_enrich.rb. Every record and identifier in the fixture is
# invented for this suite; no production OTKB fixture content is required or included.

require 'json'

begin
  require 'concurrent'
rescue LoadError
  require 'concurrent-ruby'
end

SCRIPT_PATH = ENV.fetch(
  'OTKB_ENRICH_RB',
  File.expand_path('../otkb_enrich.rb', __dir__)
)
FIXTURE_PATH = File.expand_path('fixtures/otkb_json_fixture.synthetic.json', __dir__)

abort "otkb_enrich.rb was not found at #{SCRIPT_PATH}" unless File.file?(SCRIPT_PATH)
abort "synthetic fixture was not found at #{FIXTURE_PATH}" unless File.file?(FIXTURE_PATH)

# The production script contains Logstash Ruby-filter startup tests. When the file is loaded by a
# standalone Ruby process, bare calls such as test "description" would otherwise resolve to
# Kernel#test, Ruby's file-test method. Ignore those DSL declarations here because this harness
# exercises the same code through its own tests below.
Object.class_eval do
  def test(_name, &_block); end

  private :test
end

begin
  load SCRIPT_PATH
ensure
  Object.send(:remove_method, :test)
end

class AssertionFailure < StandardError; end

module Assertions
  def assert(value, message = 'expected value to be truthy')
    raise AssertionFailure, message unless value
  end

  def refute(value, message = 'expected value to be falsey')
    raise AssertionFailure, message if value
  end

  def assert_equal(expected, actual, message = nil)
    return if expected == actual

    detail = "expected #{expected.inspect}, got #{actual.inspect}"
    raise AssertionFailure, [message, detail].compact.join(': ')
  end

  def assert_same(expected, actual, message = nil)
    return if expected.equal?(actual)

    detail = "expected #{expected.inspect} and #{actual.inspect} to be the same object"
    raise AssertionFailure, [message, detail].compact.join(': ')
  end

  def assert_nil(actual, message = nil)
    assert_equal(nil, actual, message)
  end

  def assert_includes(collection, value, message = nil)
    return if collection.include?(value)

    detail = "expected #{collection.inspect} to include #{value.inspect}"
    raise AssertionFailure, [message, detail].compact.join(': ')
  end

  def assert_raises(exception_class)
    begin
      yield
    rescue exception_class
      return
    rescue StandardError => error
      raise AssertionFailure,
            "expected #{exception_class}, got #{error.class}: #{error.message}"
    end

    raise AssertionFailure, "expected #{exception_class}, but nothing was raised"
  end
end

class SyntheticEvent
  attr_reader :data

  def initialize(data = {})
    @data = deep_copy(data)
  end

  def get(key_path)
    parse_key_path(key_path).reduce(@data) do |current, key|
      return nil unless current.is_a?(Hash)

      current[key]
    end
  end

  def set(key_path, value)
    keys = parse_key_path(key_path)
    leaf = keys.pop
    parent = keys.reduce(@data) do |current, key|
      current[key] = {} unless current[key].is_a?(Hash)
      current[key]
    end
    parent[leaf] = value
  end

  private

  def parse_key_path(key_path)
    key_path.scan(/\[([^\]]+)\]/).flatten
  end

  def deep_copy(value)
    Marshal.load(Marshal.dump(value))
  end
end

class FakeResponse
  attr_reader :body, :status

  def initialize(body:, status: 200, success: true)
    @body = body
    @status = status
    @success = success
  end

  def success?
    @success
  end
end

class FakeConnection
  Options = Struct.new(:open_timeout, :timeout)
  Request = Struct.new(:options)

  attr_reader :calls, :paths, :requests

  def initialize(*results)
    @results = results.flatten(1)
    @calls = 0
    @paths = []
    @requests = []
    @mutex = Mutex.new
  end

  def get(path)
    result = nil
    request = Request.new(Options.new)

    @mutex.synchronize do
      @calls += 1
      @paths << path
      @requests << request
      result = @results.shift
    end

    yield request if block_given?
    raise result if result.is_a?(Exception)
    raise Faraday::ConnectionFailed, 'no synthetic response was queued' if result.nil?

    result
  end
end

class FakeFaradayConnection
  attr_reader :requests, :responses

  def initialize(response)
    @response = response
    @requests = []
    @responses = []
  end

  def request(*arguments)
    @requests << arguments
  end

  def response(*arguments)
    @responses << arguments
  end

  def get(_path)
    @response
  end
end

class OtkbEnrichTestSuite
  include Assertions

  DEFAULT_PARAMS = {
    'enabled' => true,
    'otkb_url' => 'https://otkb.invalid/api/v1',
    'otkb_token' => 'synthetic-token',
    'cache_ttl' => 0,
    'ssl_verify' => false,
    'debug' => false,
    'debug_timings' => false
  }.freeze

  @tests = []

  class << self
    attr_reader :tests

    def test(name, &block)
      @tests << [name, block]
    end
  end

  def run
    failures = []

    self.class.tests.each do |name, block|
      reset_globals
      instance_exec(&block)
      puts "PASS #{name}"
    rescue StandardError => error
      failures << [name, error]
      warn "FAIL #{name}"
      warn "  #{error.class}: #{error.message}"
      Array(error.backtrace).first(5).each { |line| warn "  #{line}" }
    end

    puts
    puts "#{self.class.tests.length - failures.length} passed, #{failures.length} failed"
    failures.empty? ? 0 : 1
  ensure
    reset_globals
  end

  def reset_globals
    $otkb_json_fixture.set(nil)
    $otkb_json_fixture_retry_after.set(0.0)
    $otkb_json_fixture_refresh_mutex = Mutex.new
    $otkb_timings_logging_thread_running = false
    $otkb_timings.clear
  end

  def synthetic_body
    JSON.parse(File.read(FIXTURE_PATH))
  end

  def synthetic_checksums(version = 'v1')
    {
      'otkb.function' => "synthetic-function-checksum-#{version}",
      'otkb.protocol' => "synthetic-protocol-checksum-#{version}",
      'otkb.procedure' => "synthetic-procedure-checksum-#{version}"
    }
  end

  def new_filter(overrides = {})
    filter_instance = Object.new
    filter_instance.send(:register, DEFAULT_PARAMS.merge(overrides))
    filter_instance
  end

  def build_snapshot(
    filter_instance = new_filter,
    loaded_at = nil,
    body = nil,
    checksums = nil
  )
    loaded_at ||= filter_instance.send(:monotonic_time)
    body ||= synthetic_body
    filter_instance.send(
      :build_otkb_json_fixture_snapshot,
      body,
      loaded_at,
      checksums
    )
  end

  def install_snapshot(filter_instance, snapshot = nil)
    snapshot ||= build_snapshot(filter_instance)
    $otkb_json_fixture.set(snapshot)
    filter_instance.instance_variable_set(:@otkb_conn, FakeConnection.new)
    snapshot
  end

  def filter_event(filter_instance, data)
    event = SyntheticEvent.new(data)
    result = filter_instance.send(:filter, event)
    assert_equal(1, result.length)
    assert_same(event, result.first)
    event
  end

  test 'register parses the URL, TTL, SSL, and enable parameters' do
    filter_instance = new_filter(
      'enabled' => 'ON',
      'otkb_url' => 'https://otkb.invalid/api/v1/',
      'cache_ttl' => '45',
      'ssl_verify' => 'true',
      'verbose' => 'true'
    )

    assert_equal(true, filter_instance.instance_variable_get(:@otkb_enabled))
    assert_equal('https://otkb.invalid/api/v1', filter_instance.instance_variable_get(:@otkb_url))
    assert_equal(45, filter_instance.instance_variable_get(:@cache_ttl))
    assert_equal(true, filter_instance.instance_variable_get(:@otkb_ssl_verify))
    assert_equal(true, filter_instance.instance_variable_get(:@otkb_enrichment_verbose))
  end

  test 'register defaults to compact mode and reads verbose mode from the environment' do
    environment_name = 'OTKB_SYNTHETIC_VERBOSE_TEST'
    previous_value = ENV[environment_name]

    begin
      ENV.delete(environment_name)
      compact_filter = new_filter
      assert_equal(
        false,
        compact_filter.instance_variable_get(:@otkb_enrichment_verbose)
      )

      ENV[environment_name] = 'true'
      verbose_filter = new_filter('verbose_env' => environment_name)
      assert_equal(
        true,
        verbose_filter.instance_variable_get(:@otkb_enrichment_verbose)
      )
    ensure
      if previous_value.nil?
        ENV.delete(environment_name)
      else
        ENV[environment_name] = previous_value
      end
    end
  end

  test 'lazy connection configures Token authorization, JSON handling, and SSL verification' do
    original_faraday_new = Faraday.method(:new)
    captured = {}
    fake_faraday = FakeFaradayConnection.new(
      FakeResponse.new(body: { 'synthetic' => true })
    )

    Faraday.singleton_class.send(:define_method, :new) do |url, **options, &block|
      captured['url'] = url
      captured['options'] = options
      block.call(fake_faraday)
      fake_faraday
    end

    begin
      connection = OtkbConnLazy.new(
        'https://otkb.invalid/api/v1/',
        'synthetic-token',
        false,
        false
      )

      refute(connection.initialized?)
      response = connection.get('sync/json-fixture/')
      assert_equal({ 'synthetic' => true }, response.body)
      assert(connection.initialized?)
      assert_equal('https://otkb.invalid/api/v1/', captured['url'])
      assert_equal({ ssl: { verify: false } }, captured['options'])
      assert_includes(
        fake_faraday.requests,
        [:authorization, 'Token', 'synthetic-token']
      )
      assert_includes(fake_faraday.requests, [:url_encoded])
      assert_includes(fake_faraday.responses, [:json])
      assert_includes(fake_faraday.responses, [:raise_error])
    ensure
      Faraday.singleton_class.send(:define_method, :new, original_faraday_new)
    end
  end

  test 'disabled or unconfigured filters pass events through without fixture work' do
    disabled_filter = new_filter('enabled' => false)
    disabled_event = SyntheticEvent.new('zeek' => {}, 'network' => { 'protocol' => 'synproto' })
    assert_same(disabled_event, disabled_filter.send(:filter, disabled_event).first)
    assert_nil(disabled_event.get('[otkb]'))

    unconfigured_filter = new_filter('otkb_url' => '')
    unconfigured_event = SyntheticEvent.new(
      'zeek' => {},
      'network' => { 'protocol' => 'synproto' }
    )
    assert_same(unconfigured_event, unconfigured_filter.send(:filter, unconfigured_event).first)
    assert_nil(unconfigured_event.get('[otkb]'))
  end

  test 'rule engine handles equality, case differences, decimal/hex, and ranges' do
    engine = OtkbRuleEngine.new
    data = {
      'synthetic' => {
        'operation' => 'read',
        'function_code' => '0x10',
        'quantity' => 12
      }
    }

    assert_equal(1, engine.match_score(
      { 'log' => 'synthetic.log', 'field' => 'operation', 'eq' => 'READ' },
      data
    ))
    assert_equal(1, engine.match_score(
      { 'log' => 'synthetic', 'field' => 'function_code', 'eq' => 16 },
      data
    ))
    assert_equal(1, engine.match_score(
      { 'log' => 'synthetic', 'field' => 'quantity', 'gte' => 10, 'lte' => 20 },
      data
    ))
    assert_nil(engine.match_score(
      { 'log' => 'synthetic', 'field' => 'quantity', 'gte' => 13 },
      data
    ))
  end

  test 'rule engine scores nested AND and OR rules without allocating match arrays' do
    engine = OtkbRuleEngine.new
    data = { 'synthetic' => { 'operation' => 'READ', 'function_code' => 16 } }
    rule = {
      'and' => [
        { 'log' => 'synthetic', 'field' => 'operation', 'eq' => 'read' },
        {
          'or' => [
            { 'log' => 'synthetic', 'field' => 'function_code', 'eq' => '0x10' },
            {
              'and' => [
                { 'log' => 'synthetic', 'field' => 'function_code', 'gte' => 1 },
                { 'log' => 'synthetic', 'field' => 'function_code', 'lte' => 32 }
              ]
            }
          ]
        }
      ]
    }

    assert_equal(3, engine.match_score(rule, data))
  end

  test 'malformed and incomplete rules are safe non-matches' do
    engine = OtkbRuleEngine.new
    data = { 'synthetic' => { 'value' => 'not-a-number' } }
    malformed_rules = [
      nil,
      {},
      'not-a-rule',
      [],
      { 'and' => [] },
      { 'or' => [] },
      { 'log' => 'synthetic', 'eq' => 'value' },
      { 'log' => 'synthetic', 'field' => '', 'eq' => 'value' },
      { 'log' => 'synthetic', 'field' => 'missing', 'eq' => 'value' },
      { 'log' => 'synthetic', 'field' => 'value', 'gte' => 'broken' },
      { 'log' => 'synthetic', 'field' => 'value' }
    ]

    malformed_rules.each do |rule|
      assert_nil(engine.match_score(rule, data), "rule should not match: #{rule.inspect}")
    end
  end

  test 'snapshot builds normalized indexes and freezes all shared data' do
    filter_instance = new_filter
    snapshot = build_snapshot(filter_instance)

    protocol = snapshot['protocol_by_name']['synproto']
    assert_equal('Synthetic Protocol', protocol['name'])
    assert_same(protocol, snapshot['protocol_by_name']['synthetic-alt'])
    assert_equal('tcp', protocol['transport'][0]['protocol'])
    assert_equal(
      '00000000-0000-4000-8000-000000000303',
      snapshot['iec104_function_by_type_id']['1']['id']
    )
    assert_equal(2, snapshot['functions_by_zeek_log']['synthetic'].length)
    assert_equal(3, snapshot['procedures_by_function'][
      '00000000-0000-4000-8000-000000000302'
    ].length)
    compact = snapshot['compact_enrichment_by_function_id'][
      '00000000-0000-4000-8000-000000000302'
    ]
    assert_equal('Synthetic Specific Read', compact['function']['name'])
    assert_equal('D3-SYNTHETIC', compact['function']['otkb_classifier']['defend_id'])
    assert_nil(compact['function']['notes'])
    assert_nil(compact['function']['citations'])
    assert_equal('Synthetic Protocol', compact['protocol']['name'])
    assert_nil(compact['protocol']['transport'])
    assert_equal('Synthetic Controller', compact['procedures'][0]['asset']['name'])
    refute(snapshot['by_id']['otkb.asset'][
      '00000000-0000-4000-8000-000000000501'
    ].key?('attack_id'))
    refute(snapshot['by_id']['otkb.campaign'][
      '00000000-0000-4000-8000-000000000601'
    ].key?('attack_id'))
    assert(snapshot.frozen?)
    assert(snapshot['collections'].frozen?)
    assert(snapshot['collections']['otkb.function'][0].frozen?)
    assert_raises(FrozenError) { snapshot['version'].replace('changed') }
  end

  test 'snapshot rejects malformed API response shapes' do
    filter_instance = new_filter

    assert_raises(TypeError) do
      filter_instance.send(:build_otkb_json_fixture_snapshot, [], 1.0)
    end
    assert_raises(TypeError) do
      filter_instance.send(
        :build_otkb_json_fixture_snapshot,
        { 'version' => 'bad', 'data' => [] },
        1.0
      )
    end
    assert_raises(TypeError) do
      filter_instance.send(
        :build_otkb_json_fixture_snapshot,
        { 'version' => 'bad', 'data' => { 'otkb.protocol' => {} } },
        1.0
      )
    end
  end

  test 'Zeek enrichment selects the most-specific match and expands relationships' do
    filter_instance = new_filter('verbose' => true)
    snapshot = install_snapshot(filter_instance)
    event = filter_event(
      filter_instance,
      {
        'network' => { 'protocol' => 'SYNPROTO' },
        'event' => { 'dataset' => 'synthetic' },
        'zeek' => {
          'synthetic' => {
            'operation' => 'read',
            'function_code' => '0x10'
          }
        },
        'threat' => { 'indicator' => { 'provider' => 'preexisting' } }
      }
    )

    assert_equal(
      '00000000-0000-4000-8000-000000000302',
      event.get('[otkb][function][id]')
    )
    assert_equal('Synthetic Classifier', event.get('[otkb][function][otkb_classifier][name]'))
    assert_equal(
      'Synthetic note attached to the specific function.',
      event.get('[otkb][function][notes]')[0]['content']
    )
    assert_equal('Synthetic Reference', snapshot['by_id']['otkb.reference'][
      '00000000-0000-4000-8000-000000000001'
    ]['name'])
    assert_equal('Synthetic Section', event.get('[otkb][protocol][citations]')[0]['section'])
    assert_equal(3, event.get('[otkb][procedures]').length)
    assert_equal('Synthetic Controller', event.get('[otkb][procedures]')[0]['asset']['name'])
    refute(event.get('[otkb][procedures]')[0]['asset'].key?('attack_id'))

    assert_equal('MITRE ATT&CK for ICS', event.get('[threat][framework]'))
    assert_equal(['TA9999'], event.get('[threat][tactic][id]'))
    assert_equal(['T9998', 'T9999'], event.get('[threat][technique][id]'))
    assert_equal(['T9999.001'], event.get('[threat][technique][subtechnique][id]'))
    assert_equal('preexisting', event.get('[threat][indicator][provider]'))

    event.get('[otkb][function]')['name'] = 'event-owned copy'
    assert_equal(
      'Synthetic Specific Read',
      snapshot['by_id']['otkb.function'][
        '00000000-0000-4000-8000-000000000302'
      ]['name']
    )
    assert_equal(
      ['00000000-0000-4000-8000-000000000011'],
      snapshot['by_id']['otkb.function'][
        '00000000-0000-4000-8000-000000000302'
      ]['citations']
    )
  end

  test 'compact enrichment retains dashboard fields and threat mappings' do
    filter_instance = new_filter
    snapshot = install_snapshot(filter_instance)
    event = filter_event(
      filter_instance,
      {
        'network' => { 'protocol' => 'SYNPROTO' },
        'event' => { 'dataset' => 'synthetic' },
        'zeek' => {
          'synthetic' => {
            'operation' => 'read',
            'function_code' => '0x10'
          }
        },
        'threat' => { 'indicator' => { 'provider' => 'preexisting' } }
      }
    )

    function = event.get('[otkb][function]')
    protocol = event.get('[otkb][protocol]')
    procedures = event.get('[otkb][procedures]')

    assert_equal('00000000-0000-4000-8000-000000000302', function['id'])
    assert_equal('Synthetic Specific Read', function['name'])
    assert_equal('Synthetic Classifier', function['otkb_classifier']['name'])
    assert_equal('D3-SYNTHETIC', function['otkb_classifier']['defend_id'])
    assert_nil(function['notes'])
    assert_nil(function['citations'])
    assert(function['zeek_rules'].is_a?(Hash))
    assert(function['wireshark_rules'].is_a?(Hash))

    assert_equal('Synthetic Protocol', protocol['name'])
    assert_nil(protocol['description'])
    assert_nil(protocol['transport'])
    assert_nil(protocol['citations'])

    assert_equal(3, procedures.length)
    assert_equal('TA9999', procedures[0]['attack_id'])
    assert_equal('Synthetic Controller', procedures[0]['asset']['name'])
    assert_equal('Synthetic Campaign', procedures[0]['campaign']['name'])
    assert_equal('Synthetic Utility', procedures[0]['software']['name'])
    assert_nil(procedures[0]['id'])
    assert_nil(procedures[0]['description'])
    assert_nil(procedures[0]['citations'])

    assert_equal('MITRE ATT&CK for ICS', event.get('[threat][framework]'))
    assert_equal(['TA9999'], event.get('[threat][tactic][id]'))
    assert_equal(['T9998', 'T9999'], event.get('[threat][technique][id]'))
    assert_equal(['T9999.001'], event.get('[threat][technique][subtechnique][id]'))
    assert_equal('preexisting', event.get('[threat][indicator][provider]'))

    function['name'] = 'event-owned compact copy'
    assert_equal(
      'Synthetic Specific Read',
      snapshot['compact_enrichment_by_function_id'][
        '00000000-0000-4000-8000-000000000302'
      ]['function']['name']
    )
  end

  test 'Wireshark enrichment uses nested fields and decimal/hex equivalence' do
    filter_instance = new_filter
    install_snapshot(filter_instance)
    event = filter_event(
      filter_instance,
      {
        'network' => { 'protocol' => ['synproto'] },
        'wireshark' => {
          'synthetic' => {
            'operation' => 'READ',
            'function_code' => 16
          }
        }
      }
    )

    assert_equal(
      '00000000-0000-4000-8000-000000000302',
      event.get('[otkb][function][id]')
    )
  end

  test 'IEC 104 symbolic ASDU type uses the direct function index' do
    filter_instance = new_filter
    install_snapshot(filter_instance)
    event = filter_event(
      filter_instance,
      {
        'network' => { 'protocol' => 'iec104' },
        'event' => { 'dataset' => 'iec104_telemetry' },
        'zeek' => {
          'iec104_telemetry' => {
            'asdu_type' => 'M_SP_NA_1'
          }
        }
      }
    )

    assert_equal(
      '00000000-0000-4000-8000-000000000303',
      event.get('[otkb][function][id]')
    )
    assert_equal('1', filter_instance.send(:normalize_iec104_type_id, 'M_SP_NA_1'))
    assert_equal('200', filter_instance.send(:normalize_iec104_type_id, 'ASDU_TYPE_200'))
    assert_equal('UNKNOWN_TYPE', filter_instance.send(:normalize_iec104_type_id, 'UNKNOWN_TYPE'))
  end

  test 'equal-score matches use function ID as a deterministic tie-breaker' do
    filter_instance = new_filter
    install_snapshot(filter_instance)
    event = filter_event(
      filter_instance,
      {
        'network' => { 'protocol' => 'tieproto' },
        'event' => { 'dataset' => 'tieproto' },
        'zeek' => { 'tieproto' => { 'operation' => 'PING' } }
      }
    )

    assert_equal(
      '00000000-0000-4000-8000-000000000304',
      event.get('[otkb][function][id]')
    )
  end

  test 'unsupported events and nonmatching rules pass through unchanged' do
    filter_instance = new_filter
    install_snapshot(filter_instance)

    unsupported = SyntheticEvent.new('network' => { 'protocol' => 'synproto' })
    unsupported_before = Marshal.load(Marshal.dump(unsupported.data))
    filter_instance.send(:filter, unsupported)
    assert_equal(unsupported_before, unsupported.data)

    no_match = filter_event(
      filter_instance,
      {
        'network' => { 'protocol' => 'synproto' },
        'zeek' => { 'synthetic' => { 'operation' => 'WRITE', 'function_code' => 99 } }
      }
    )
    assert_nil(no_match.get('[otkb]'))
  end

  test 'initial API load uses the expected path and request timeouts' do
    filter_instance = new_filter
    connection = FakeConnection.new(
      FakeResponse.new(body: synthetic_checksums),
      FakeResponse.new(body: synthetic_body)
    )
    filter_instance.instance_variable_set(:@otkb_conn, connection)

    snapshot = filter_instance.send(:get_otkb_json_fixture)

    assert_equal('synthetic-test-v1', snapshot['version'])
    assert_equal(synthetic_checksums, snapshot['checksums'])
    assert_equal(2, connection.calls)
    assert_equal(['sync/checksum/', 'sync/json-fixture/'], connection.paths)
    assert_equal(5, connection.requests[0].options.open_timeout)
    assert_equal(30, connection.requests[0].options.timeout)
    assert_equal(5, connection.requests[1].options.open_timeout)
    assert_equal(30, connection.requests[1].options.timeout)
    assert_same(snapshot, $otkb_json_fixture.get)
  end

  test 'fresh TTL snapshot is reused without another API request' do
    filter_instance = new_filter('cache_ttl' => 300)
    snapshot = build_snapshot(filter_instance)
    connection = FakeConnection.new
    filter_instance.instance_variable_set(:@otkb_conn, connection)
    $otkb_json_fixture.set(snapshot)

    assert_same(snapshot, filter_instance.send(:get_otkb_json_fixture))
    assert_same(snapshot, filter_instance.send(:get_otkb_json_fixture))
    assert_equal(0, connection.calls)
  end

  test 'expired TTL snapshot is replaced by a successful refresh' do
    filter_instance = new_filter('cache_ttl' => 1)
    old_snapshot = build_snapshot(
      filter_instance,
      filter_instance.send(:monotonic_time) - 10,
      nil,
      synthetic_checksums('v1')
    )
    refreshed_body = synthetic_body
    refreshed_body['version'] = 'synthetic-test-v2'
    connection = FakeConnection.new(
      FakeResponse.new(body: synthetic_checksums('v2')),
      FakeResponse.new(body: refreshed_body)
    )
    filter_instance.instance_variable_set(:@otkb_conn, connection)
    $otkb_json_fixture.set(old_snapshot)

    refreshed = filter_instance.send(:get_otkb_json_fixture)

    assert_equal('synthetic-test-v2', refreshed['version'])
    assert_equal(synthetic_checksums('v2'), refreshed['checksums'])
    assert_equal(2, connection.calls)
    assert_equal(['sync/checksum/', 'sync/json-fixture/'], connection.paths)
    refute(old_snapshot.equal?(refreshed))
  end

  test 'unchanged checksums advance freshness without loading the full fixture' do
    filter_instance = new_filter('cache_ttl' => 1)
    old_snapshot = build_snapshot(
      filter_instance,
      filter_instance.send(:monotonic_time) - 10,
      nil,
      synthetic_checksums
    )
    connection = FakeConnection.new(
      FakeResponse.new(body: synthetic_checksums)
    )
    filter_instance.instance_variable_set(:@otkb_conn, connection)
    $otkb_json_fixture.set(old_snapshot)

    checked = filter_instance.send(:get_otkb_json_fixture)

    assert_equal(1, connection.calls)
    assert_equal(['sync/checksum/'], connection.paths)
    assert_equal(old_snapshot['version'], checked['version'])
    assert_same(old_snapshot['collections'], checked['collections'])
    assert_same(
      old_snapshot['compact_enrichment_by_function_id'],
      checked['compact_enrichment_by_function_id']
    )
    assert(
      checked['_checksum_checked_at_monotonic'] >
      old_snapshot['_checksum_checked_at_monotonic']
    )
    refute(old_snapshot.equal?(checked))
  end

  test 'failed refresh retains the old snapshot and suppresses immediate retries' do
    filter_instance = new_filter('cache_ttl' => 1)
    old_snapshot = build_snapshot(filter_instance, filter_instance.send(:monotonic_time) - 10)
    connection = FakeConnection.new(
      Faraday::ConnectionFailed.new('synthetic connection failure')
    )
    filter_instance.instance_variable_set(:@otkb_conn, connection)
    $otkb_json_fixture.set(old_snapshot)

    assert_same(old_snapshot, filter_instance.send(:get_otkb_json_fixture))
    assert_same(old_snapshot, filter_instance.send(:get_otkb_json_fixture))
    assert_equal(1, connection.calls)
    assert($otkb_json_fixture_retry_after.get > filter_instance.send(:monotonic_time))
  end

  test 'failed full fixture load retains the old checksum baseline' do
    filter_instance = new_filter('cache_ttl' => 1)
    old_checksums = synthetic_checksums('v1')
    old_snapshot = build_snapshot(
      filter_instance,
      filter_instance.send(:monotonic_time) - 10,
      nil,
      old_checksums
    )
    connection = FakeConnection.new(
      FakeResponse.new(body: synthetic_checksums('v2')),
      Faraday::ConnectionFailed.new('synthetic fixture connection failure')
    )
    filter_instance.instance_variable_set(:@otkb_conn, connection)
    $otkb_json_fixture.set(old_snapshot)

    assert_same(old_snapshot, filter_instance.send(:get_otkb_json_fixture))
    assert_equal(old_checksums, $otkb_json_fixture.get['checksums'])
    assert_equal(2, connection.calls)
    assert_equal(['sync/checksum/', 'sync/json-fixture/'], connection.paths)
    assert($otkb_json_fixture_retry_after.get > filter_instance.send(:monotonic_time))
  end

  test 'filter clones with the same URL share one cached snapshot' do
    first_filter = new_filter
    second_filter = new_filter
    first_connection = FakeConnection.new(
      FakeResponse.new(body: synthetic_checksums),
      FakeResponse.new(body: synthetic_body)
    )
    second_connection = FakeConnection.new
    first_filter.instance_variable_set(:@otkb_conn, first_connection)
    second_filter.instance_variable_set(:@otkb_conn, second_connection)

    first_snapshot = first_filter.send(:get_otkb_json_fixture)
    second_snapshot = second_filter.send(:get_otkb_json_fixture)

    assert_same(first_snapshot, second_snapshot)
    assert_equal(2, first_connection.calls)
    assert_equal(0, second_connection.calls)
  end

  test 'filter clones with different base URLs do not share snapshots' do
    first_filter = new_filter('otkb_url' => 'https://one.invalid/api/v1')
    second_filter = new_filter('otkb_url' => 'https://two.invalid/api/v1')
    first_connection = FakeConnection.new(
      FakeResponse.new(body: synthetic_checksums('one')),
      FakeResponse.new(body: synthetic_body)
    )
    second_body = synthetic_body
    second_body['version'] = 'synthetic-second-source'
    second_connection = FakeConnection.new(
      FakeResponse.new(body: synthetic_checksums('two')),
      FakeResponse.new(body: second_body)
    )
    first_filter.instance_variable_set(:@otkb_conn, first_connection)
    second_filter.instance_variable_set(:@otkb_conn, second_connection)

    first_snapshot = first_filter.send(:get_otkb_json_fixture)
    second_snapshot = second_filter.send(:get_otkb_json_fixture)

    assert_equal('https://one.invalid/api/v1', first_snapshot['source_url'])
    assert_equal('https://two.invalid/api/v1', second_snapshot['source_url'])
    assert_equal('synthetic-second-source', second_snapshot['version'])
    assert_equal(2, first_connection.calls)
    assert_equal(2, second_connection.calls)
  end

  test 'concurrent first use publishes one complete snapshot with one API refresh sequence' do
    filters = Array.new(8) { new_filter }
    connection = FakeConnection.new(
      FakeResponse.new(body: synthetic_checksums),
      FakeResponse.new(body: synthetic_body)
    )
    filters.each { |filter_instance| filter_instance.instance_variable_set(:@otkb_conn, connection) }

    snapshots = filters.map do |filter_instance|
      Thread.new { filter_instance.send(:get_otkb_json_fixture) }
    end.map(&:value)

    assert_equal(2, connection.calls)
    assert_equal(['sync/checksum/', 'sync/json-fixture/'], connection.paths)
    assert(snapshots.all? { |snapshot| snapshot.equal?(snapshots.first) })
    assert(snapshots.first.frozen?)
  end
end

exit OtkbEnrichTestSuite.new.run
