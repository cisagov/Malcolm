def concurrency
  :shared
end

require 'faraday'
require 'json'
require 'tempfile'
require 'time'

##############################################################################################
# The fixture and its refresh state are global so every clone of this filter in this Logstash
# process reads the same immutable snapshot. A different Logstash process has its own snapshot.
$otkb_json_fixture ||= Concurrent::AtomicReference.new(nil)
$otkb_json_fixture_refresh_mutex ||= Mutex.new
$otkb_json_fixture_retry_after ||= Concurrent::AtomicReference.new(0.0)

##############################################################################################
# These global variables generate optional performance profiling stats for OTKB API calls.
$otkb_timings_logging_thread_started ||= Concurrent::AtomicFixnum.new(0)
$otkb_timings ||= Concurrent::Map.new
$otkb_timings_logging_thread ||= nil
$otkb_timings_logging_thread_running ||= false

##############################################################################################
# Zeek serializes IEC 60870-5-104 ASDU type IDs using the symbolic enum names
# below, while OTKB rules use their numeric values.
# Adapted from https://github.com/cert-lv/spicy-iec104/blob/main/scripts/iec104.zeek
OTKB_IEC104_TYPE_IDS = {
  'ASDU_TYPEUNDEF' => '0',
  'M_SP_NA_1' => '1',
  'M_SP_TA_1' => '2',
  'M_DP_NA_1' => '3',
  'M_DP_TA_1' => '4',
  'M_ST_NA_1' => '5',
  'M_ST_TA_1' => '6',
  'M_BO_NA_1' => '7',
  'M_BO_TA_1' => '8',
  'M_ME_NA_1' => '9',
  'M_ME_TA_1' => '10',
  'M_ME_NB_1' => '11',
  'M_ME_TB_1' => '12',
  'M_ME_NC_1' => '13',
  'M_ME_TC_1' => '14',
  'M_IT_NA_1' => '15',
  'M_IT_TA_1' => '16',
  'M_EP_TA_1' => '17',
  'M_EP_TB_1' => '18',
  'M_EP_TC_1' => '19',
  'M_PS_NA_1' => '20',
  'M_ME_ND_1' => '21',
  'M_SP_TB_1' => '30',
  'M_DP_TB_1' => '31',
  'M_ST_TB_1' => '32',
  'M_BO_TB_1' => '33',
  'M_ME_TD_1' => '34',
  'M_ME_TE_1' => '35',
  'M_ME_TF_1' => '36',
  'M_IT_TB_1' => '37',
  'M_EP_TD_1' => '38',
  'M_EP_TE_1' => '39',
  'M_EP_TF_1' => '40',
  'C_SC_NA_1' => '45',
  'C_DC_NA_1' => '46',
  'C_RC_NA_1' => '47',
  'C_SE_NA_1' => '48',
  'C_SE_NB_1' => '49',
  'C_SE_NC_1' => '50',
  'C_BO_NA_1' => '51',
  'C_SC_TA_1' => '58',
  'C_DC_TA_1' => '59',
  'C_RC_TA_1' => '60',
  'C_SE_TA_1' => '61',
  'C_SE_TB_1' => '62',
  'C_SE_TC_1' => '63',
  'C_BO_TA_1' => '64',
  'M_EI_NA_1' => '70',
  'C_IC_NA_1' => '100',
  'C_CI_NA_1' => '101',
  'C_RD_NA_1' => '102',
  'C_CS_NA_1' => '103',
  'C_TS_NA_1' => '104',
  'C_RP_NA_1' => '105',
  'C_CD_NA_1' => '106',
  'C_TS_TA_1' => '107',
  'P_ME_NA_1' => '110',
  'P_ME_NB_1' => '111',
  'P_ME_NC_1' => '112',
  'P_AC_NA_1' => '113',
  'F_FR_NA_1' => '120',
  'F_SR_NA_1' => '121',
  'F_SC_NA_1' => '122',
  'F_LS_NA_1' => '123',
  'F_AF_NA_1' => '124',
  'F_SG_NA_1' => '125',
  'F_DR_TA_1' => '126',
  'F_SC_NB_1' => '127'
}.freeze

# Compact enrichment keeps the fields recommended for general use along with fields already used
# by Malcolm's OTKB dashboard. Related records are reduced separately below.
OTKB_COMPACT_FUNCTION_FIELDS = %w[
  created_at
  description
  function_code
  id
  message_type
  name
  origin_node
  protocol
  specification_classifier
  wireshark_rules
  zeek_rules
].freeze
OTKB_COMPACT_CLASSIFIER_FIELDS = %w[
  definition
  defend_id
  name
].freeze
OTKB_COMPACT_PROTOCOL_FIELDS = %w[
  alternate_names
  id
  name
  wireshark_dissector
  zeek_parser
].freeze
OTKB_COMPACT_PROCEDURE_FIELDS = %w[
  attack_id
].freeze
OTKB_COMPACT_PROCEDURE_RELATION_FIELDS = %w[
  attack_id
  name
].freeze

##############################################################################################
# Creates the Faraday connection the first time it is used. Keeping this wrapper lazy allows the
# pipeline to start when enrichment is disabled or the OTKB URL has not been configured.
class OtkbConnLazy
  def initialize(
    url,
    token,
    ssl_verify,
    debug
  )
    @object = nil
    @url = url
    @token = token
    @ssl_verify = ssl_verify
    @conn_debug = debug
    @connected = false
  end

  def method_missing(method, *args, &block)
    puts "#{method}(#{args.map(&:inspect).join(', ')})" if @conn_debug

    # API timings are collected here so the normal request path does not need separate timing
    # code for every Faraday method we might call.
    if $otkb_timings_logging_thread_running
      key = "#{method} #{args[0]}".to_sym
      start_time = Time.now
    end

    initialize_object unless @object
    result = @object.send(method, *args, &block)

    if $otkb_timings_logging_thread_running
      duration = (Time.now - start_time) * 1000
      $otkb_timings.compute_if_absent(key) { Concurrent::Array.new } << duration
    end

    @connected ||= !result.nil?
    result
  end

  def respond_to_missing?(method, include_private = false)
    initialize_object unless @object
    @object.respond_to?(method, include_private) || super
  end

  def initialized?
    # A constructed Faraday object does not prove the endpoint is reachable. Treat the wrapper as
    # initialized after the first request returns a result.
    !@object.nil? && @connected
  end

  private

  def initialize_object
    # Faraday joins relative request paths to this base URL. The API expects the token scheme in
    # the form "Authorization: Token <token>".
    @object = Faraday.new(@url, ssl: { verify: @ssl_verify }) do |conn|
      unless @token.nil? || @token.to_s.empty?
        conn.request :authorization, 'Token', @token
      end
      conn.request :url_encoded
      conn.response :json
      conn.response :raise_error
    end
    @connected = false
  end
end

##############################################################################################
# Evaluates the rule objects stored in zeek_rules and wireshark_rules.
class OtkbRuleEngine
  # This boolean form is useful to callers that do not need to rank multiple matches.
  def match?(rule, event_data)
    !match_score(rule, event_data).nil?
  end

  # Return the number of leaf conditions in the matching path. A nil score means the rule did not
  # match. The score lets the filter prefer a narrower match when several functions match an event.
  def match_score(rule, event_data)
    case rule
    when Hash
      if rule.key?('and')
        match_all(rule['and'], event_data)
      elsif rule.key?('or')
        match_any(rule['or'], event_data)
      else
        match_single_rule(rule, event_data) ? 1 : nil
      end
    when Array
      match_all(rule, event_data)
    else
      nil
    end
  end

  private

  def match_all(rules, event_data)
    return nil unless rules.is_a?(Array) && !rules.empty?

    # Stop on the first failed branch. A successful AND scores as the sum of all matching leaves.
    total = 0
    rules.each do |subrule|
      score = match_score(subrule, event_data)
      return nil if score.nil?

      total += score
    end
    total
  end

  def match_any(rules, event_data)
    return nil unless rules.is_a?(Array) && !rules.empty?

    # Only the most-specific matching OR branch contributes to the score.
    best = nil
    rules.each do |subrule|
      score = match_score(subrule, event_data)
      best = score if !score.nil? && (best.nil? || score > best)
    end
    best
  end

  def match_single_rule(rule, event_data)
    field_path = rule['field']
    return false unless field_path.is_a?(String) && !field_path.empty?

    if rule.key?('log')
      # Zeek rules store the log and field separately. Event data is nested by normalized log name,
      # so combine the two here before walking the event hash.
      log_type = normalize_log_name(rule['log'])
      field_path = "#{log_type}.#{field_path}"
    end

    value = dig_field(event_data, field_path)
    return false if value.nil?

    return rule_values_equal?(value, rule['eq']) if rule.key?('eq')

    # Range comparisons are numeric. Malformed limits or nonnumeric event values simply make the
    # rule a non-match so a bad upstream rule cannot interrupt event processing.
    begin
      numeric_value = Float(value)
      if rule.key?('gte') && rule.key?('lte')
        return numeric_value >= Float(rule['gte']) && numeric_value <= Float(rule['lte'])
      end

      return numeric_value >= Float(rule['gte']) if rule.key?('gte')
      return numeric_value <= Float(rule['lte']) if rule.key?('lte')
    rescue ArgumentError, TypeError
      return false
    end

    false
  end

  def comparable_integer(string)
    # Treat decimal and hexadecimal strings as the same integer for protocols that format numeric
    # identifiers differently between Zeek, Wireshark, and the fixture.
    if string.match?(/\A0[xX][0-9a-fA-F]+\z/)
      Integer(string[2..], 16)
    elsif string.match?(/\A[+-]?\d+\z/)
      Integer(string, 10)
    end
  rescue ArgumentError, TypeError
    nil
  end

  def rule_values_equal?(actual, expected)
    actual_string = actual.to_s.strip
    expected_string = expected.to_s.strip

    # Most values match here. Besides being faster, this handles symbolic protocol values whose
    # capitalization differs between the parser and the fixture.
    return true if actual_string.casecmp?(expected_string)

    actual_integer = comparable_integer(actual_string)
    expected_integer = comparable_integer(expected_string)

    !actual_integer.nil? &&
      !expected_integer.nil? &&
      actual_integer == expected_integer
  end

  def normalize_log_name(value)
    value.to_s.sub(/\.log\z/, '').tr('-', '_').sub(/_general\z/, '')
  end

  def dig_field(hash, field_path)
    # Return nil when an intermediate value is missing or is not an object. Rules can therefore
    # reference optional fields without raising an exception.
    field_path.split('.').reduce(hash) do |value, key|
      value.is_a?(Hash) ? value[key] : nil
    end
  end
end

##############################################################################################
# Read script parameters once for this filter instance. Parameters may contain literal values or
# the names of environment variables, which keeps secrets and deployment settings out of the
# pipeline configuration.
def register(
  params
)
  # Enable or disable the filter using a script parameter or global environment variable.
  _enabled_str = params['enabled']
  _enabled_env = params['enabled_env']
  if _enabled_str.nil? && !_enabled_env.nil?
    _enabled_str = ENV[_enabled_env]
  end
  @otkb_enabled = [1, true, '1', 'true', 't', 'on', 'enabled'].include?(_enabled_str.to_s.downcase)

  # Refresh the complete fixture after this many seconds. Zero loads it once per process.
  _cache_ttl_val = integer_or_nil(params['cache_ttl'])
  _cache_ttl_env = params['cache_ttl_env']
  if (_cache_ttl_val.nil? || _cache_ttl_val.negative?) && !_cache_ttl_env.nil?
    _cache_ttl_val = integer_or_nil(ENV[_cache_ttl_env])
  end
  @cache_ttl = if !_cache_ttl_val.nil? && _cache_ttl_val >= 0
                 _cache_ttl_val
               else
                 300
               end

  _debug_str = params['debug']
  _debug_env = params['debug_env']
  if _debug_str.nil? && !_debug_env.nil?
    _debug_str = ENV[_debug_env]
  end
  @debug_verbose = ['verbose', 'v', 'extra'].include?(_debug_str.to_s.downcase)
  @debug = @debug_verbose || [1, true, '1', 'true', 't', 'on', 'enabled'].include?(_debug_str.to_s.downcase)

  # Compact enrichment is the default because the same OTKB metadata may be repeated across many
  # events. Verbose mode retains the complete expanded records for deployments that need them.
  _verbose_str = params['verbose']
  _verbose_env = params['verbose_env']
  if _verbose_str.nil? && !_verbose_env.nil?
    _verbose_str = ENV[_verbose_env]
  end
  @otkb_enrichment_verbose = [1, true, '1', 'true', 't', 'on', 'enabled'].include?(_verbose_str.to_s.downcase)

  # API timing collection is separate from normal debug output because it starts a background
  # reporting thread and retains individual request durations.
  _debug_timings_str = params['debug_timings']
  _debug_timings_env = params['debug_timings_env']
  if _debug_timings_str.nil? && !_debug_timings_env.nil?
    _debug_timings_str = ENV[_debug_timings_env]
  end
  @debug_timings = [1, true, '1', 'true', 't', 'on', 'enabled'].include?(_debug_timings_str.to_s.downcase)

  # OTKB API base URL, specified directly or read from an environment variable.
  @otkb_url = params['otkb_url'].to_s.delete_suffix('/')
  _otkb_url_env = params['otkb_url_env'].to_s
  if @otkb_url.empty? && !_otkb_url_env.empty?
    @otkb_url = ENV[_otkb_url_env].to_s.delete_suffix('/')
  end
  @otkb_url = nil if @otkb_url.empty?

  # Optional path to a complete JSON fixture. A valid file seeds the shared fixture during
  # registration, which also allows enrichment to operate without an API connection.
  @otkb_json_fixture_file = params['otkb_json_fixture_file'].to_s
  _otkb_json_fixture_file_env = params['otkb_json_fixture_file_env'].to_s
  if @otkb_json_fixture_file.empty? && !_otkb_json_fixture_file_env.empty?
    @otkb_json_fixture_file = ENV[_otkb_json_fixture_file_env].to_s
  end
  @otkb_json_fixture_file = nil if @otkb_json_fixture_file.empty?

  # OTKB API token, specified directly or read from the first populated environment variable.
  @otkb_token = params['otkb_token']
  _otkb_token_env = params['otkb_token_env']
  if @otkb_token.nil? && !_otkb_token_env.nil?
    @otkb_token = _otkb_token_env.split(/[;,:\s]+/)
                                 .map { |env| ENV[env].to_s }
                                 .find { |value| !value.strip.empty? }
  end

  _ssl_verify_str = params['ssl_verify']
  _ssl_verify_env = params['ssl_verify_env']
  if _ssl_verify_str.nil? && !_ssl_verify_env.nil?
    _ssl_verify_str = ENV[_ssl_verify_env]
  end
  @otkb_ssl_verify = [1, true, '1', 'true', 't', 'on'].include?(_ssl_verify_str.to_s.downcase)

  # Leave the connection nil when no URL is configured. filter can then return immediately without
  # attempting any API or fixture work.
  @otkb_conn = OtkbConnLazy.new(
    "#{@otkb_url}/",
    @otkb_token,
    @otkb_ssl_verify,
    @debug_verbose
  ) unless @otkb_url.nil?
  @otkb_rule_engine = OtkbRuleEngine.new

  # Load the local file before events begin flowing. When an API is also configured, this snapshot
  # remains available immediately and is replaced by an API response after the normal TTL expires.
  if @otkb_enabled && !@otkb_json_fixture_file.nil?
    # A file that cannot supply a snapshot is treated as though the parameter was not specified.
    # This allows an API configuration to continue normally and restores the inexpensive early
    # return for a filter that has neither a usable file nor an API URL.
    @otkb_json_fixture_file = nil if load_otkb_json_fixture_file.nil?
  end

  # Filter clones share one timing thread. The atomic compare-and-set makes thread creation safe
  # when several clones register at the same time.
  if @debug_timings &&
     $otkb_timings_logging_thread_started.value == 0 &&
     $otkb_timings_logging_thread_started.compare_and_set(0, 1)
    $otkb_timings_logging_thread = Thread.new { log_otkb_timings_thread_proc }
    $otkb_timings_logging_thread_running = true
  end
end

##############################################################################################
# Match the event against OTKB functions for its parser and network protocol, then attach the
# selected function, its protocol, any related procedures, and derived ATT&CK fields.
def filter(
  event
)
  return [event] unless @otkb_enabled
  return [event] if @otkb_conn.nil? && @otkb_json_fixture_file.nil?

  # Prefer the parser-specific object already present on the event. Pipeline-level guards normally
  # limit calls to these two event shapes, and this check keeps the script safe on other events.
  _event_data = event.get('[zeek]')
  if _event_data.is_a?(Hash)
    _parser = :zeek
    _rule_field = 'zeek_rules'
  else
    _event_data = event.get('[wireshark]')
    return [event] unless _event_data.is_a?(Hash)

    _parser = :wireshark
    _rule_field = 'wireshark_rules'
  end

  _protocol_name = event.get('[network][protocol]')
  # ECS fields may be scalar or arrays. OTKB currently performs one protocol lookup per event, so
  # use the first value when Logstash has promoted the field to an array.
  _protocol_name = _protocol_name.first if _protocol_name.is_a?(Array)
  return [event] unless _protocol_name.is_a?(String) && !_protocol_name.empty?

  # This call returns the current snapshot and refreshes it from sync/json-fixture/ when its TTL
  # has expired. A failed refresh leaves the previous snapshot available to this event.
  _fixture = get_otkb_json_fixture
  return [event] if _fixture.nil?

  _protocol_name_normalized = normalize_index_key(_protocol_name)

  # protocol_by_name includes both canonical names and alternate names from the fixture.
  _protocol = _fixture['protocol_by_name'][_protocol_name_normalized]
  return [event] unless _protocol.is_a?(Hash)

  _direct_function = nil

  # Zeek stores IEC 104 fields under dataset-specific objects and serializes
  # ASDU type IDs using symbolic enum names. OTKB uses iec104.info_obj_type
  # with numeric string values.
  if _parser == :zeek && _protocol_name_normalized == 'iec104'
    _dataset = event.get('[event][dataset]')
    _dataset = _dataset.first if _dataset.is_a?(Array)

    if _dataset.is_a?(String)
      _iec104_data = _event_data[normalize_log_name(_dataset)]

      if _iec104_data.is_a?(Hash) && !_iec104_data['asdu_type'].nil?
        _iec104_type_id =
          normalize_iec104_type_id(_iec104_data['asdu_type'])

        _direct_function =
          _fixture['iec104_function_by_type_id'][_iec104_type_id.to_s]

        # Preserve the synthetic field for generic matching when this ASDU
        # type does not have a directly indexed simple equality rule.
        unless _direct_function.is_a?(Hash)
          _event_data = _event_data.dup
          _event_data['iec104'] = {
            'info_obj_type' => _iec104_type_id
          }
        end
      end
    end
  end

  if _direct_function.is_a?(Hash)
    # Every directly indexed IEC 104 rule contains one equality leaf, so its match score is one.
    _match = {
      'function' => _direct_function,
      'score' => 1
    }
  else
    # All other traffic, along with IEC 104 types that do not qualify for the direct index, uses the
    # general rule engine so compound and range-based rules retain their normal behavior.
    _functions =
      _fixture['functions_by_protocol'].fetch(_protocol['id'], [])

    _best_function = nil
    _best_score = nil

    _functions.each do |function|
      next unless function.is_a?(Hash)

      rule = function[_rule_field]
      next if rule.nil?

      begin
        score = @otkb_rule_engine.match_score(rule, _event_data)
      rescue StandardError => error
        if @debug
          puts "Invalid OTKB rule for function #{function['id']}: " \
               "#{error.class}: #{error.message}"
        end
        next
      end

      next if score.nil?

      # Prefer the matching rule with the most satisfied leaf conditions.
      # Sort equal scores by UUID so fixture ordering cannot affect selection.
      if _best_function.nil? ||
         score > _best_score ||
         (
           score == _best_score &&
           function['id'].to_s < _best_function['id'].to_s
         )
        _best_function = function
        _best_score = score
      end
    end

    if _best_function.nil?
      if @debug_verbose
        puts "No OTKB #{_parser} match for protocol #{_protocol_name}"
      end
      return [event]
    end

    _match = {
      'function' => _best_function,
      'score' => _best_score
    }
  end

  _function = _match['function']
  _procedures = _fixture['procedures_by_function'].fetch(_function['id'], [])

  if @otkb_enrichment_verbose
    # Verbose mode expands all linked records for users who need the complete OTKB context. Only
    # objects written to the event are copied, leaving the shared fixture immutable.
    event.set('[otkb][function]', enrich_otkb_function(_function, _fixture))
    event.set('[otkb][protocol]', enrich_otkb_citations(_protocol, _fixture))

    unless _procedures.empty?
      _enriched_procedures = _procedures.map { |procedure| enrich_otkb_procedure(procedure, _fixture) }
      event.set('[otkb][procedures]', _enriched_procedures)
    end
  else
    # Compact payloads are assembled once per fixture refresh. Copying one prepared payload avoids
    # resolving citations and linked records, then pruning them again, for every matching event.
    _compact_enrichment =
      _fixture.fetch('compact_enrichment_by_function_id', {})[_function['id']]
    event.set('[otkb]', deep_copy(_compact_enrichment)) if _compact_enrichment.is_a?(Hash)
  end

  # ATT&CK fields are derived from the complete cached procedure records in both output modes.
  # Compact mode can therefore omit most procedure metadata without losing threat enrichment.
  enrich_threat_from_otkb_procedures(event, _procedures) unless _procedures.empty?

  puts "Matched OTKB function #{_function['id']} (#{_function['name']}) with score #{_match['score']}" if @debug_verbose

  if @otkb_enrichment_verbose
    _otkb = event.get('[otkb]')

    if _otkb.is_a?(Hash)
      _otkb = crush(_otkb)

      if _otkb.empty?
        event.remove('[otkb]')
      else
        event.set('[otkb]', _otkb)
      end
    end
  end

  [event]

  [event]
end

##############################################################################################
# Prepare the selected function for insertion into the event. Foreign-key IDs are replaced with
# their fixture records, and function notes are attached from their separate collection.
def enrich_otkb_function(function, fixture)
  enriched = enrich_otkb_citations(function, fixture)

  classifier = otkb_fixture_record(fixture, 'otkb.otkbclass', function['otkb_classifier'])
  if classifier.nil?
    enriched.delete('otkb_classifier')
  else
    enriched['otkb_classifier'] = deep_copy(classifier)
  end

  notes = fixture['function_notes_by_function'].fetch(function['id'], [])
  enriched['notes'] = deep_copy(notes) unless notes.empty?
  enriched
end

##############################################################################################
# Expand the records related to a procedure. Missing relationships are removed instead of leaving
# a mixture of IDs and objects in the indexed event.
def enrich_otkb_procedure(procedure, fixture)
  enriched = enrich_otkb_citations(procedure, fixture)
  {
    'asset' => 'otkb.asset',
    'software' => 'otkb.software',
    'campaign' => 'otkb.campaign'
  }.each_pair do |field, collection|
    related = otkb_fixture_record(fixture, collection, procedure[field])
    if related.nil?
      enriched.delete(field)
    else
      enriched[field] = enrich_otkb_citations(related, fixture)
    end
  end
  enriched
end

##############################################################################################
# Fixture citations may already be embedded objects or may be IDs into otkb.citation. Always return
# copied objects so event mutation cannot alter the globally shared snapshot.
def enrich_otkb_citations(record, fixture)
  enriched = deep_copy(record)
  return enriched unless record.is_a?(Hash) && record['citations'].is_a?(Array)

  enriched['citations'] = record['citations'].map do |citation|
    if citation.is_a?(Hash)
      deep_copy(citation)
    else
      found = otkb_fixture_record(fixture, 'otkb.citation', citation)
      deep_copy(found) unless found.nil?
    end
  end.compact
  enriched
end

##############################################################################################
# Select fields for the compact event representation without modifying the complete fixture
# record. Empty values are removed once while the snapshot is built.
def compact_otkb_record(record, fields)
  return {} unless record.is_a?(Hash)

  selected = fields.each_with_object({}) do |field, result|
    result[field] = record[field] if record.key?(field)
  end
  crush(selected)
end

##############################################################################################
# Build one ready-to-copy compact payload for each function. This work happens only when a fixture
# is loaded, keeping relationship resolution and field selection out of the per-event path.
def build_compact_otkb_enrichment_by_function_id(
  functions,
  procedures_by_function,
  by_id
)
  compact_protocol_by_id = by_id.fetch('otkb.protocol', {}).each_with_object({}) do |(id, protocol), index|
    index[id] = compact_otkb_record(protocol, OTKB_COMPACT_PROTOCOL_FIELDS)
  end

  compact_classifier_by_id = by_id.fetch('otkb.otkbclass', {}).each_with_object({}) do |(id, classifier), index|
    index[id] = compact_otkb_record(classifier, OTKB_COMPACT_CLASSIFIER_FIELDS)
  end

  compact_related_by_collection = {
    'asset' => 'otkb.asset',
    'campaign' => 'otkb.campaign',
    'software' => 'otkb.software'
  }.each_with_object({}) do |(field, collection), indexes|
    indexes[field] = by_id.fetch(collection, {}).each_with_object({}) do |(id, record), index|
      index[id] = compact_otkb_record(
        record,
        OTKB_COMPACT_PROCEDURE_RELATION_FIELDS
      )
    end
  end

  functions.each_with_object({}) do |function, index|
    next unless function.is_a?(Hash)

    function_id = function['id']
    next if function_id.nil? || function_id.to_s.empty?

    compact_function = compact_otkb_record(
      function,
      OTKB_COMPACT_FUNCTION_FIELDS
    )
    classifier = compact_classifier_by_id[function['otkb_classifier']]
    compact_function['otkb_classifier'] = classifier unless classifier.nil? || classifier.empty?

    payload = {
      'function' => compact_function
    }

    protocol = compact_protocol_by_id[function['protocol']]
    payload['protocol'] = protocol unless protocol.nil? || protocol.empty?

    procedures = procedures_by_function.fetch(function_id, []).filter_map do |procedure|
      next unless procedure.is_a?(Hash)

      compact_procedure = compact_otkb_record(
        procedure,
        OTKB_COMPACT_PROCEDURE_FIELDS
      )
      compact_related_by_collection.each_pair do |field, related_index|
        related = related_index[procedure[field]]
        compact_procedure[field] = related unless related.nil? || related.empty?
      end
      compact_procedure unless compact_procedure.empty?
    end
    payload['procedures'] = procedures unless procedures.empty?

    index[function_id] = payload
  end
end

##############################################################################################
# Look up one fixture record through the collection-specific ID indexes built during refresh.
def otkb_fixture_record(fixture, collection, id)
  return nil if id.nil? || id.to_s.empty?

  collection_index = fixture.fetch('by_id', {}).fetch(collection, {})
  collection_index[id]
end

##############################################################################################
# Convert ATT&CK IDs on matched procedures into the ECS threat fields used by the rest of the
# pipeline. Names are filled in later by the Logstash translate filters.
def enrich_threat_from_otkb_procedures(event, procedures)
  threat = event.get('[threat]')
  threat = threat.is_a?(Hash) ? deep_copy(threat) : {}
  matched_attack_id = false

  procedures.each do |procedure|
    attack_id = procedure['attack_id'].to_s
    case attack_id
    when /\ATA\d+\z/
      # TA identifiers represent tactics.
      append_unique_nested_value(threat, ['tactic', 'id'], attack_id)
      append_unique_nested_value(
        threat,
        ['tactic', 'reference'],
        "https://attack.mitre.org/tactics/#{attack_id}/"
      )
      matched_attack_id = true
    when /\AT\d+\.\d+\z/
      # ECS stores a subtechnique under its parent technique. Preserve the full ID and build the
      # reference path using the parent and child portions expected by attack.mitre.org.
      technique_id, subtechnique_id = attack_id.split('.', 2)
      append_unique_nested_value(threat, ['technique', 'id'], technique_id)
      append_unique_nested_value(
        threat,
        ['technique', 'reference'],
        "https://attack.mitre.org/techniques/#{technique_id}/"
      )
      append_unique_nested_value(threat, ['technique', 'subtechnique', 'id'], attack_id)
      append_unique_nested_value(
        threat,
        ['technique', 'subtechnique', 'reference'],
        "https://attack.mitre.org/techniques/#{technique_id}/#{subtechnique_id}/"
      )
      matched_attack_id = true
    when /\AT\d+\z/
      # T identifiers without a decimal portion represent top-level techniques.
      append_unique_nested_value(threat, ['technique', 'id'], attack_id)
      append_unique_nested_value(
        threat,
        ['technique', 'reference'],
        "https://attack.mitre.org/techniques/#{attack_id}/"
      )
      matched_attack_id = true
    end
  end

  if matched_attack_id
    threat['framework'] = 'MITRE ATT&CK for ICS'
    event.set('[threat]', threat)
  end
end

##############################################################################################
# Append one value at an arbitrary nested path without overwriting threat data produced by another
# filter. The leaf is kept as an array because one event may map to several procedures.
def append_unique_nested_value(hash, path, value)
  parent = path[0...-1].reduce(hash) do |current, key|
    current[key] = {} unless current[key].is_a?(Hash)
    current[key]
  end
  leaf = path.last
  values = Array(parent[leaf]).compact
  values << value unless values.include?(value)
  parent[leaf] = values
end

##############################################################################################
# Return the current immutable fixture snapshot. One worker refreshes it when needed while other
# workers continue using the previous snapshot. During the initial load, workers wait for the
# loading worker because there is no previous snapshot to use.
def get_otkb_json_fixture
  _now = monotonic_time
  _fixture = $otkb_json_fixture.get
  _fixture = nil unless otkb_json_fixture_source_matches?(_fixture)

  return _fixture if otkb_json_fixture_fresh?(_fixture, _now)
  # A file-only fixture has no remote source to refresh. Keep using its immutable snapshot for the
  # life of this Logstash process, regardless of the configured API cache TTL.
  return _fixture if @otkb_conn.nil?
  return _fixture if _now < $otkb_json_fixture_retry_after.get

  # When a refresh is already running, keep using the previous snapshot. On the initial load,
  # _fixture is nil, so workers continue to the mutex and wait for the loading worker.
  if !_fixture.nil? && $otkb_json_fixture_refresh_mutex.locked?
    return _fixture
  end

  # Repeat all checks after taking the mutex because another worker may have refreshed the fixture
  # while this worker was waiting.
  $otkb_json_fixture_refresh_mutex.synchronize do
    _now = monotonic_time
    _fixture = $otkb_json_fixture.get
    _fixture = nil unless otkb_json_fixture_source_matches?(_fixture)

    return _fixture if otkb_json_fixture_fresh?(_fixture, _now)
    return _fixture if _now < $otkb_json_fixture_retry_after.get

    # Check the inexpensive checksum endpoint before requesting the complete fixture. The first
    # API load has no checksum baseline, so it continues through to the full fixture request.
    begin
      _checksums = get_otkb_json_fixture_checksums
      _stored_checksums = _fixture['checksums'] if _fixture.is_a?(Hash)

      if _stored_checksums.is_a?(Hash) && _stored_checksums == _checksums
        # Keep the same immutable fixture data and indexes while advancing the successful check
        # time used by the TTL. A shallow copy is sufficient because the existing snapshot and
        # every object reachable from it were frozen before publication.
        _checksum_checked_at_monotonic = monotonic_time
        _snapshot = _fixture.merge(
          'checksum_checked_at' => Time.now.utc.iso8601(6),
          '_checksum_checked_at_monotonic' => _checksum_checked_at_monotonic
        ).freeze
        $otkb_json_fixture.set(_snapshot)
        $otkb_json_fixture_retry_after.set(0.0)

        puts 'OTKB JSON fixture checksums are unchanged' if @debug

        return _snapshot
      end

      # At least one collection was added, removed, or changed. Rebuild all indexes from the new
      # complete fixture before replacing the global reference.
      _response = @otkb_conn.get('sync/json-fixture/') do |request|
        request.options.open_timeout = 5
        request.options.timeout = 30
      end
      unless _response.success?
        raise Faraday::Error,
              "OTKB fixture request returned HTTP #{_response.status}"
      end

      _snapshot = build_otkb_json_fixture_snapshot(
        _response.body,
        monotonic_time,
        _checksums
      )
      $otkb_json_fixture.set(_snapshot)
      $otkb_json_fixture_retry_after.set(0.0)

      if @debug
        puts "Loaded OTKB JSON fixture version #{_snapshot['version']} " \
             "generated at #{_snapshot['generated_at']}"
      end

      _snapshot
    # A refresh failure does not discard a previously loaded fixture. Initial-load failures return
    # nil, causing events to pass through without enrichment until the retry window expires.
    rescue Faraday::Error, JSON::ParserError, ArgumentError, TypeError => error
      # Start the retry window when the request fails. Calculating this after the request keeps the
      # complete delay intact when a connection or response timeout takes several seconds.
      _retry_delay = @cache_ttl.zero? ? 60 : [[@cache_ttl, 60].min, 1].max
      $otkb_json_fixture_retry_after.set(
        monotonic_time + _retry_delay
      )

      if @debug
        puts "OTKB JSON fixture refresh failed: " \
             "#{error.class}: #{error.message}"
      end

      _fixture
    end
  end
end

##############################################################################################
# Request and validate the collection checksum map used to decide whether the complete fixture
# needs to be downloaded. The checksum format itself belongs to the server, so only the response
# shape and nonempty string values are enforced here.
def get_otkb_json_fixture_checksums
  response = @otkb_conn.get('sync/checksum/') do |request|
    request.options.open_timeout = 5
    request.options.timeout = 30
  end
  unless response.success?
    raise Faraday::Error,
          "OTKB checksum request returned HTTP #{response.status}"
  end

  checksums = response.body.is_a?(String) ? JSON.parse(response.body) : response.body
  unless checksums.is_a?(Hash) && !checksums.empty?
    raise TypeError, 'OTKB checksum response must be a nonempty object'
  end

  normalized_checksums = {}
  checksums.each_pair do |collection_name, checksum|
    unless collection_name.is_a?(String) &&
           !collection_name.empty? &&
           checksum.is_a?(String) &&
           !checksum.empty?
      raise TypeError,
            'OTKB checksum response must contain nonempty string keys and values'
    end

    normalized_checksums[collection_name] = checksum
  end

  normalized_checksums
end

##############################################################################################
# Load a complete fixture from disk and publish it through the same immutable global snapshot used
# by API responses. The mutex prevents filter clones from parsing and publishing duplicate copies.
def load_otkb_json_fixture_file
  unless File.file?(@otkb_json_fixture_file)
    if @otkb_enabled
      puts "OTKB JSON fixture file was not found: #{@otkb_json_fixture_file}"
    end
    return nil
  end

  $otkb_json_fixture_refresh_mutex.synchronize do
    _fixture = $otkb_json_fixture.get
    return _fixture if otkb_json_fixture_source_matches?(_fixture)

    _snapshot = build_otkb_json_fixture_snapshot(
      File.read(@otkb_json_fixture_file),
      monotonic_time
    )
    $otkb_json_fixture.set(_snapshot)
    $otkb_json_fixture_retry_after.set(0.0)

    if @debug
      puts "Loaded OTKB JSON fixture version #{_snapshot['version']} " \
           "generated at #{_snapshot['generated_at']} " \
           "from #{@otkb_json_fixture_file}"
    end

    _snapshot
  end
rescue SystemCallError, IOError, JSON::ParserError, ArgumentError, TypeError => error
  if @otkb_enabled
    puts "OTKB JSON fixture file load failed: " \
         "#{error.class}: #{error.message}"
  end
  nil
end

##############################################################################################
# Use the API URL as the shared cache identity when one is configured. Otherwise the fixture's
# full file path identifies file-only filter clones that can safely share one snapshot.
def otkb_json_fixture_source_key
  return "url:#{@otkb_url}" unless @otkb_url.nil?
  return "file:#{@otkb_json_fixture_file}" unless @otkb_json_fixture_file.nil?

  nil
end

##############################################################################################
# A global snapshot may be shared by several filter clones or pipelines. Only reuse it when its
# API URL or file-only path matches the source configured for this filter instance.
def otkb_json_fixture_source_matches?(fixture)
  source_key = otkb_json_fixture_source_key
  !source_key.nil? &&
    fixture.is_a?(Hash) &&
    fixture['source_key'] == source_key
end

##############################################################################################
# TTL zero means load once for the life of the Logstash process. Positive TTL values are measured
# from a monotonic timestamp so wall-clock adjustments cannot make a snapshot unexpectedly stale.
def otkb_json_fixture_fresh?(fixture, now)
  return false unless otkb_json_fixture_source_matches?(fixture)
  return true if @otkb_conn.nil?
  return true if @cache_ttl.zero?

  checked_at = fixture['_checksum_checked_at_monotonic'] || fixture['_loaded_at_monotonic']
  checked_at.is_a?(Numeric) && (now - checked_at) < @cache_ttl
end

##############################################################################################
# Validate and normalize the API response, build the indexes used by filter, and freeze the final
# object before publishing it through the global atomic reference.
def build_otkb_json_fixture_snapshot(
  response_body,
  loaded_at_monotonic,
  checksums = nil
)
  body = response_body.is_a?(String) ? JSON.parse(response_body) : response_body
  raise TypeError, 'OTKB JSON fixture response must be an object' unless body.is_a?(Hash)

  collections = body['data']
  raise TypeError, 'OTKB JSON fixture data must be an object' unless collections.is_a?(Hash)

  # Normalize values that otherwise vary in representation before building indexes or exposing
  # records to event enrichment.
  normalize_otkb_protocol_transports!(collections.fetch('otkb.protocol', []))
  normalize_otkb_attack_ids!(collections)

  # Most relationships in the fixture are UUID references. Build one ID index per collection so
  # later joins do not scan the source arrays for every enriched event.
  by_id = {}
  collections.each_pair do |collection_name, records|
    raise TypeError, "OTKB fixture collection #{collection_name} must be an array" unless records.is_a?(Array)

    by_id[collection_name] = records.each_with_object({}) do |record, index|
      next unless record.is_a?(Hash)

      id = record['id']
      index[id] = record unless id.nil? || id.to_s.empty?
    end
  end

  protocols = collections.fetch('otkb.protocol', [])
  functions = collections.fetch('otkb.function', [])
  function_notes = collections.fetch('otkb.functionnote', [])
  procedures = collections.fetch('otkb.procedure', [])

  # network.protocol may contain a canonical OTKB name or one of its alternate names. Point every
  # normalized spelling at the same protocol record.
  protocol_by_name = {}
  protocols.each do |protocol|
    next unless protocol.is_a?(Hash)

    ([protocol['name']] + Array(protocol['alternate_names'])).compact.each do |name|
      key = normalize_index_key(name)
      protocol_by_name[key] ||= protocol unless key.empty?
    end
  end

  # These one-to-many indexes cover the joins performed for every matched function.
  functions_by_protocol = group_records_by_field(functions, 'protocol')
  function_notes_by_function = group_records_by_field(function_notes, 'function')
  procedures_by_function = group_records_by_field(procedures, 'function')
  compact_enrichment_by_function_id =
    build_compact_otkb_enrichment_by_function_id(
      functions,
      procedures_by_function,
      by_id
    )

  # Index simple IEC 104 equality rules by numeric ASDU type ID. This lets the
  # filter bypass the generic rule engine for the common IEC 104 match path.
  iec104_function_by_type_id = {}
  iec104_protocol = protocol_by_name['iec104']

  if iec104_protocol.is_a?(Hash)
    iec104_protocol_id = iec104_protocol['id']

    Array(functions_by_protocol[iec104_protocol_id]).each do |function|
      next unless function.is_a?(Hash)

      rule = function['zeek_rules']
      next unless rule.is_a?(Hash)
      next unless rule['field'] == 'info_obj_type'
      next unless normalize_log_name(rule['log']) == 'iec104'
      next unless rule.key?('eq')

      # Compound or extended rules continue through the generic rule engine.
      next unless (rule.keys - %w[field log eq]).empty?

      type_id = rule['eq'].to_s
      next if type_id.empty?

      existing = iec104_function_by_type_id[type_id]

      # Preserve the generic matcher's deterministic UUID tie-break behavior.
      if existing.nil? ||
         function['id'].to_s < existing['id'].to_s
        iec104_function_by_type_id[type_id] = function
      end
    end
  end

  # Record which functions mention each Zeek log anywhere in their rule tree. Keeping this in the
  # snapshot also makes the fixture ready for narrower log-based candidate selection in the future.
  functions_by_zeek_log = Hash.new { |hash, key| hash[key] = [] }
  functions.each do |function|
    next unless function.is_a?(Hash)

    rule_values(function['zeek_rules'], 'log').map { |log_name| normalize_log_name(log_name) }.uniq.each do |log_name|
      functions_by_zeek_log[log_name] << function unless log_name.empty?
    end
  end
  functions_by_zeek_log.default = nil

  # Store a human-readable load time for diagnostics and a monotonic time for TTL calculations.
  loaded_at = Time.now.utc
  snapshot = {
    'version' => body['version'],
    'generated_at' => body['generated_at'],
    'loaded_at' => loaded_at.iso8601(6),
    'source_key' => otkb_json_fixture_source_key,
    'source_url' => @otkb_url&.dup,
    'source_file' => @otkb_json_fixture_file&.dup,
    'collections' => collections,
    'by_id' => by_id,
    'protocol_by_name' => protocol_by_name,
    'functions_by_protocol' => functions_by_protocol,
    'functions_by_zeek_log' => functions_by_zeek_log,
    'iec104_function_by_type_id' => iec104_function_by_type_id,
    'function_notes_by_function' => function_notes_by_function,
    'procedures_by_function' => procedures_by_function,
    'compact_enrichment_by_function_id' => compact_enrichment_by_function_id,
    '_loaded_at_monotonic' => loaded_at_monotonic
  }
  unless checksums.nil?
    snapshot['checksums'] = checksums
    snapshot['checksum_checked_at'] = loaded_at.iso8601(6)
    snapshot['_checksum_checked_at_monotonic'] = loaded_at_monotonic
  end

  deep_freeze(snapshot)
end

##############################################################################################
# Group records by one foreign-key field. Set the default back to nil before freezing the index so
# a missing lookup cannot try to modify a frozen hash through its construction-time default proc.
def group_records_by_field(records, field)
  index = Hash.new { |hash, key| hash[key] = [] }
  records.each do |record|
    next unless record.is_a?(Hash)

    value = record[field]
    index[value] << record unless value.nil? || value.to_s.empty?
  end
  index.default = nil
  index
end

##############################################################################################
# Recursively collect values for one key from a rule tree. This is used for metadata such as the
# Zeek log names referenced inside nested AND and OR expressions.
def rule_values(rule, key, values = [])
  case rule
  when Hash
    values << rule[key] if rule.key?(key)
    rule.each_value { |value| rule_values(value, key, values) }
  when Array
    rule.each { |value| rule_values(value, key, values) }
  end
  values.compact
end

##############################################################################################
# Convert Zeek log filenames and variants to the object names used under the event's [zeek] field.
def normalize_log_name(value)
  value.to_s.sub(/\.log\z/, '').tr('-', '_').sub(/_general\z/, '')
end

##############################################################################################
# Convert the symbolic IEC 104 ASDU values emitted by Zeek to the numeric strings used by OTKB.
# Unknown values are returned unchanged so they can safely fall through to the generic matcher.
def normalize_iec104_type_id(value)
  return nil if value.nil?

  string = value.to_s

  type_id = OTKB_IEC104_TYPE_IDS[string]
  return type_id unless type_id.nil?

  # Zeek represents reserved or unnamed values as ASDU_TYPE_<number>.
  match = /\AASDU_TYPE_(\d{1,3})\z/.match(string)
  return value if match.nil?

  numeric_type_id = Integer(match[1], 10)
  return numeric_type_id.to_s if numeric_type_id.between?(0, 255)

  value
rescue ArgumentError, TypeError
  value
end

##############################################################################################
# Keep transport protocols consistent with ECS network.transport values and with values already
# written elsewhere in the pipeline.
def normalize_otkb_protocol_transports!(protocols)
  protocols.each do |protocol|
    next unless protocol.is_a?(Hash)

    Array(protocol['transport']).each do |transport|
      next unless transport.is_a?(Hash)

      value = transport['protocol']
      transport['protocol'] = value.strip.downcase if value.is_a?(String)
    end
  end
end

##############################################################################################
# Remove blank ATT&CK IDs from fixture records. Empty strings are not useful enrichment values and
# would otherwise survive into both [otkb] and ECS [threat] fields.
def normalize_otkb_attack_ids!(collections)
  [
    'otkb.procedure',
    'otkb.asset',
    'otkb.software',
    'otkb.campaign'
  ].each do |collection_name|
    Array(collections[collection_name]).each do |record|
      next unless record.is_a?(Hash)

      attack_id = record['attack_id']
      if attack_id.nil? || (attack_id.is_a?(String) && attack_id.strip.empty?)
        record.delete('attack_id')
      end
    end
  end
end

##############################################################################################
# Names used as lookup keys are case-insensitive, with surrounding whitespace ignored.
def normalize_index_key(value)
  value.to_s.strip.downcase
end

##############################################################################################
# Use monotonic time for elapsed-time comparisons because it is unaffected by NTP or clock changes.
def monotonic_time
  Process.clock_gettime(Process::CLOCK_MONOTONIC)
end

##############################################################################################
# Parse optional integer parameters without raising during pipeline registration.
def integer_or_nil(value)
  return value if value.is_a?(Integer)

  Integer(value, exception: false)
end


##############################################################################################
# Periodically report API request timings collected by OtkbConnLazy. The thread is started only
# when debug timing is enabled and is shared by all clones of this filter.
def log_otkb_timings_thread_proc
  while $otkb_timings_logging_thread_running
    sleep 60
    puts 'Method Execution Timings ---------------- :'
    $otkb_timings.each do |method, times|
      total_time = times.empty? ? 0 : times.sum
      avg_time = times.empty? ? 0 : total_time / times.size
      puts "#{method}: total #{total_time.round(2)} ms, avg #{avg_time.round(2)} ms over #{times.size} calls"
    end
  end
end

##############################################################################################
# Recursively freeze a fixture snapshot before sharing it across Logstash workers and pipelines.
def deep_freeze(object)
  case object
  when Hash
    object.each_pair do |key, value|
      deep_freeze(key)
      deep_freeze(value)
    end
  when Array
    object.each { |value| deep_freeze(value) }
  end
  object.freeze
end

##############################################################################################
# Produce an independent event-owned value from a frozen fixture record. Marshal preserves the
# nested hashes and arrays used throughout the JSON fixture.
def deep_copy(object)
  Marshal.load(Marshal.dump(object))
end

##############################################################################################
# Recursively removes empty values from nested Ruby arrays and hashes.
def crush(thing)
  if thing.is_a?(Array)
    thing.each_with_object([]) do |v, a|
      v = crush(v)
      a << v unless [nil, [], {}, ""].include?(v)
    end
  elsif thing.is_a?(Hash)
    thing.each_with_object({}) do |(k,v), h|
      v = crush(v)
      h[k] = v unless [nil, [], {}, ""].include?(v)
    end
  else
    thing
  end
end

##############################################################################################
# tests
#
# These startup tests use only invented records and identifiers. The fixture is built through the
# same snapshot builder used for API responses, then loaded from a temporary local file. No test
# opens a network connection.

OTKB_INLINE_TEST_FIXTURE = deep_freeze(
  {
    'version' => 'synthetic-inline-test-v1',
    'generated_at' => '2000-01-01T00:00:00.000000+00:00Z',
    'data' => {
      'otkb.reference' => [
        {
          'id' => 'reference-synthetic',
          'name' => 'Synthetic Reference'
        }
      ],
      'otkb.author' => [],
      'otkb.citation' => [
        {
          'id' => 'citation-synthetic',
          'reference' => 'reference-synthetic',
          'section' => 'Synthetic Section'
        }
      ],
      'otkb.protocol' => [
        {
          'id' => 'protocol-synthetic',
          'name' => 'Synthetic Protocol',
          'alternate_names' => ['synproto'],
          'transport' => [
            {
              'protocol' => ' TCP ',
              'port' => 12_345
            }
          ],
          'citations' => ['citation-synthetic']
        },
        {
          'id' => 'protocol-iec104',
          'name' => 'IEC104',
          'alternate_names' => ['iec104', 'IEC 104'],
          'transport' => [
            {
              'protocol' => 'Tcp',
              'port' => 2404
            }
          ]
        },
        {
          'id' => 'protocol-tie',
          'name' => 'Tie Protocol',
          'alternate_names' => ['tieproto'],
          'transport' => []
        }
      ],
      'otkb.term' => [],
      'otkb.otkbclass' => [
        {
          'id' => 'classifier-synthetic',
          'name' => 'Synthetic Classifier',
          'definition' => 'Invented classifier used only by startup tests.',
          'defend_id' => 'd3f:SyntheticCommand'
        }
      ],
      'otkb.function' => [
        {
          'id' => 'function-general',
          'name' => 'Synthetic General Read',
          'protocol' => 'protocol-synthetic',
          'zeek_rules' => {
            'log' => 'synthetic.log',
            'field' => 'operation',
            'eq' => 'READ'
          },
          'wireshark_rules' => {
            'field' => 'synthetic.operation',
            'eq' => 'READ'
          }
        },
        {
          'id' => 'function-specific',
          'name' => 'Synthetic Specific Read',
          'protocol' => 'protocol-synthetic',
          'otkb_classifier' => 'classifier-synthetic',
          'citations' => ['citation-synthetic'],
          'zeek_rules' => {
            'and' => [
              {
                'log' => 'synthetic.log',
                'field' => 'operation',
                'eq' => 'READ'
              },
              {
                'log' => 'synthetic.log',
                'field' => 'function_code',
                'eq' => '16'
              }
            ]
          },
          'wireshark_rules' => {
            'and' => [
              {
                'field' => 'synthetic.operation',
                'eq' => 'READ'
              },
              {
                'field' => 'synthetic.function_code',
                'eq' => '0x10'
              }
            ]
          }
        },
        {
          'id' => 'function-iec104-1',
          'name' => 'Synthetic IEC 104 Single Point',
          'protocol' => 'protocol-iec104',
          'zeek_rules' => {
            'log' => 'iec104',
            'field' => 'info_obj_type',
            'eq' => '1'
          }
        },
        {
          'id' => 'function-tie-a',
          'name' => 'Synthetic Tie Winner',
          'protocol' => 'protocol-tie',
          'zeek_rules' => {
            'log' => 'tieproto',
            'field' => 'operation',
            'eq' => 'PING'
          }
        },
        {
          'id' => 'function-tie-b',
          'name' => 'Synthetic Tie Runner-up',
          'protocol' => 'protocol-tie',
          'zeek_rules' => {
            'log' => 'tieproto',
            'field' => 'operation',
            'eq' => 'PING'
          }
        }
      ],
      'otkb.functionnote' => [
        {
          'id' => 'note-synthetic',
          'function' => 'function-specific',
          'content' => 'Synthetic function note.'
        }
      ],
      'otkb.asset' => [
        {
          'id' => 'asset-synthetic',
          'name' => 'Synthetic Controller',
          'attack_id' => '   '
        }
      ],
      'otkb.campaign' => [],
      'otkb.software' => [],
      'otkb.procedure' => [
        {
          'id' => 'procedure-tactic',
          'function' => 'function-specific',
          'attack_id' => 'TA9999',
          'asset' => 'asset-synthetic'
        },
        {
          'id' => 'procedure-technique',
          'function' => 'function-specific',
          'attack_id' => 'T9998'
        },
        {
          'id' => 'procedure-subtechnique',
          'function' => 'function-specific',
          'attack_id' => 'T9999.001'
        }
      ]
    }
  }
)

# Keep the temporary file open for the life of the script so the file-only startup test can pass
# its path through the normal register parameters without depending on an external fixture.
OTKB_INLINE_TEST_FIXTURE_TEMPFILE = Tempfile.new(
  ['otkb-inline-test-fixture-', '.json']
)
OTKB_INLINE_TEST_FIXTURE_TEMPFILE.write(
  JSON.generate(OTKB_INLINE_TEST_FIXTURE)
)
OTKB_INLINE_TEST_FIXTURE_TEMPFILE.flush

##############################################################################################
test 'OTKB rule values handle case, hexadecimal, and numeric ranges' do
  parameters do
    {
      'enabled' => false,
      'debug_timings' => false
    }
  end

  in_event { {} }

  expect('rule values match their normalized representations') do |_events|
    engine = OtkbRuleEngine.new
    data = {
      'synthetic' => {
        'operation' => 'read',
        'function_code' => '0x10',
        'quantity' => 12
      }
    }

    engine.match_score(
      {
        'log' => 'synthetic.log',
        'field' => 'operation',
        'eq' => 'READ'
      },
      data
    ) == 1 &&
      engine.match_score(
        {
          'log' => 'synthetic',
          'field' => 'function_code',
          'eq' => 16
        },
        data
      ) == 1 &&
      engine.match_score(
        {
          'log' => 'synthetic',
          'field' => 'quantity',
          'gte' => 10,
          'lte' => 20
        },
        data
      ) == 1
  end
end

##############################################################################################
test 'OTKB rule scoring handles nested AND and OR branches' do
  parameters do
    {
      'enabled' => false,
      'debug_timings' => false
    }
  end

  in_event { {} }

  expect('the most-specific successful OR branch contributes to the score') do |_events|
    engine = OtkbRuleEngine.new
    rule = {
      'and' => [
        {
          'log' => 'synthetic',
          'field' => 'operation',
          'eq' => 'read'
        },
        {
          'or' => [
            {
              'log' => 'synthetic',
              'field' => 'function_code',
              'eq' => '0x10'
            },
            {
              'and' => [
                {
                  'log' => 'synthetic',
                  'field' => 'function_code',
                  'gte' => 1
                },
                {
                  'log' => 'synthetic',
                  'field' => 'function_code',
                  'lte' => 32
                }
              ]
            }
          ]
        }
      ]
    }
    data = {
      'synthetic' => {
        'operation' => 'READ',
        'function_code' => 16
      }
    }

    engine.match_score(rule, data) == 3
  end
end

##############################################################################################
test 'malformed OTKB rules are safe non-matches' do
  parameters do
    {
      'enabled' => false,
      'debug_timings' => false
    }
  end

  in_event { {} }

  expect('malformed rules do not raise or match') do |_events|
    engine = OtkbRuleEngine.new
    data = {
      'synthetic' => {
        'value' => 'not-a-number'
      }
    }
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

    malformed_rules.all? { |rule| engine.match_score(rule, data).nil? }
  end
end

##############################################################################################
test 'OTKB enriches a synthetic Zeek event' do
  parameters do
    {
      'enabled' => true,
      'otkb_json_fixture_file' => OTKB_INLINE_TEST_FIXTURE_TEMPFILE.path,
      'cache_ttl' => 0,
      'verbose' => true,
      'debug' => false,
      'debug_timings' => false
    }
  end

  in_event do
    {
      'network' => {
        'protocol' => 'SYNPROTO'
      },
      'event' => {
        'dataset' => 'synthetic'
      },
      'zeek' => {
        'synthetic' => {
          'operation' => 'read',
          'function_code' => '0x10'
        }
      },
      'threat' => {
        'indicator' => {
          'provider' => 'preexisting'
        }
      }
    }
  end

  expect('the more-specific function and its relationships are written') do |events|
    event = events.first
    function = event.get('[otkb][function]')
    protocol = event.get('[otkb][protocol]')
    procedures = event.get('[otkb][procedures]')
    cached_function = $otkb_json_fixture.get['by_id']['otkb.function']['function-specific']

    events.length == 1 &&
      function['id'] == 'function-specific' &&
      function['otkb_classifier']['name'] == 'Synthetic Classifier' &&
      function['notes'][0]['content'] == 'Synthetic function note.' &&
      function['citations'][0]['section'] == 'Synthetic Section' &&
      protocol['transport'][0]['protocol'] == 'tcp' &&
      procedures.length == 3 &&
      procedures[0]['asset']['name'] == 'Synthetic Controller' &&
      !procedures[0]['asset'].key?('attack_id') &&
      event.get('[threat][framework]') == 'MITRE ATT&CK for ICS' &&
      event.get('[threat][tactic][id]') == ['TA9999'] &&
      event.get('[threat][technique][id]') == ['T9998', 'T9999'] &&
      event.get('[threat][technique][subtechnique][id]') == ['T9999.001'] &&
      event.get('[threat][indicator][provider]') == 'preexisting' &&
      cached_function['citations'] == ['citation-synthetic']
  end
end

##############################################################################################
test 'OTKB compact enrichment retains dashboard fields and threat mappings' do
  parameters do
    {
      'enabled' => true,
      'otkb_json_fixture_file' => OTKB_INLINE_TEST_FIXTURE_TEMPFILE.path,
      'cache_ttl' => 0,
      'verbose' => false,
      'debug' => false,
      'debug_timings' => false
    }
  end

  in_event do
    {
      'network' => {
        'protocol' => 'synproto'
      },
      'event' => {
        'dataset' => 'synthetic'
      },
      'zeek' => {
        'synthetic' => {
          'operation' => 'READ',
          'function_code' => 16
        }
      }
    }
  end

  expect('compact output omits expanded metadata while retaining dashboard fields') do |events|
    event = events.first
    function = event.get('[otkb][function]')
    protocol = event.get('[otkb][protocol]')
    procedures = event.get('[otkb][procedures]')

    events.length == 1 &&
      function['id'] == 'function-specific' &&
      function['otkb_classifier']['name'] == 'Synthetic Classifier' &&
      function['otkb_classifier']['defend_id'] == 'd3f:SyntheticCommand' &&
      function['notes'].nil? &&
      function['citations'].nil? &&
      protocol['name'] == 'Synthetic Protocol' &&
      protocol['transport'].nil? &&
      procedures[0]['attack_id'] == 'TA9999' &&
      procedures[0]['asset']['name'] == 'Synthetic Controller' &&
      event.get('[threat][framework]') == 'MITRE ATT&CK for ICS' &&
      event.get('[threat][tactic][id]') == ['TA9999']
  end
end

##############################################################################################
test 'OTKB enriches a synthetic Wireshark event' do
  parameters do
    {
      'enabled' => true,
      'otkb_json_fixture_file' => OTKB_INLINE_TEST_FIXTURE_TEMPFILE.path,
      'cache_ttl' => 0,
      'debug' => false,
      'debug_timings' => false
    }
  end

  in_event do
    {
      'network' => {
        'protocol' => ['synproto']
      },
      'wireshark' => {
        'synthetic' => {
          'operation' => 'READ',
          'function_code' => 16
        }
      }
    }
  end

  expect('nested fields and hexadecimal values select the specific function') do |events|
    events.length == 1 &&
      events.first.get('[otkb][function][id]') == 'function-specific'
  end
end

##############################################################################################
test 'OTKB maps a symbolic IEC 104 ASDU type through the direct index' do
  parameters do
    {
      'enabled' => true,
      'otkb_json_fixture_file' => OTKB_INLINE_TEST_FIXTURE_TEMPFILE.path,
      'cache_ttl' => 0,
      'debug' => false,
      'debug_timings' => false
    }
  end

  in_event do
    {
      'network' => {
        'protocol' => 'iec104'
      },
      'event' => {
        'dataset' => 'iec104_telemetry'
      },
      'zeek' => {
        'iec104_telemetry' => {
          'asdu_type' => 'M_SP_NA_1'
        }
      }
    }
  end

  expect('the numeric type ID selects the indexed function') do |events|
    events.length == 1 &&
      events.first.get('[otkb][function][id]') == 'function-iec104-1'
  end
end

##############################################################################################
test 'OTKB resolves equal-score matches by function ID' do
  parameters do
    {
      'enabled' => true,
      'otkb_json_fixture_file' => OTKB_INLINE_TEST_FIXTURE_TEMPFILE.path,
      'cache_ttl' => 0,
      'debug' => false,
      'debug_timings' => false
    }
  end

  in_event do
    {
      'network' => {
        'protocol' => 'tieproto'
      },
      'event' => {
        'dataset' => 'tieproto'
      },
      'zeek' => {
        'tieproto' => {
          'operation' => 'PING'
        }
      }
    }
  end

  expect('the lexically lower function ID wins') do |events|
    events.length == 1 &&
      events.first.get('[otkb][function][id]') == 'function-tie-a'
  end
end

##############################################################################################
test 'OTKB leaves a nonmatching supported event unenriched' do
  parameters do
    {
      'enabled' => true,
      'otkb_json_fixture_file' => OTKB_INLINE_TEST_FIXTURE_TEMPFILE.path,
      'cache_ttl' => 0,
      'debug' => false,
      'debug_timings' => false
    }
  end

  in_event do
    {
      'network' => {
        'protocol' => 'synproto'
      },
      'zeek' => {
        'synthetic' => {
          'operation' => 'WRITE',
          'function_code' => 99
        }
      }
    }
  end

  expect('the event passes through without an OTKB object') do |events|
    events.length == 1 && events.first.get('[otkb]').nil?
  end
end

##############################################################################################
test 'OTKB enriches from a local fixture without an API URL' do
  parameters do
    {
      'enabled' => true,
      'otkb_json_fixture_file' => OTKB_INLINE_TEST_FIXTURE_TEMPFILE.path,
      'cache_ttl' => 1,
      'debug' => false,
      'debug_timings' => false
    }
  end

  in_event do
    {
      'network' => {
        'protocol' => 'synproto'
      },
      'event' => {
        'dataset' => 'synthetic'
      },
      'zeek' => {
        'synthetic' => {
          'operation' => 'READ',
          'function_code' => 16
        }
      }
    }
  end

  expect('the file-only fixture remains available without an API connection') do |events|
    fixture = $otkb_json_fixture.get

    events.length == 1 &&
      events.first.get('[otkb][function][id]') == 'function-specific' &&
      fixture['source_url'].nil? &&
      fixture['source_file'] == OTKB_INLINE_TEST_FIXTURE_TEMPFILE.path
  end
end

##############################################################################################
