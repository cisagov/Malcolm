def concurrency
  :shared
end

require 'date'
require 'faraday'
require 'fuzzystringmatch'
require 'ipaddr'
require 'json'
require 'lru_reredux'
require 'psych'
require 'uri'
require 'stringex_lite'

##############################################################################################
# Despite the warning against globla variables, we are using them here in order to make sure that
#   we don't have duplicate caches for things cross different clones of the filter,
#   which is what happens if you just use @instance_variables. However, we should
#   be safe because 1) we are using Concurrent::Hash to maintain these per-type caches, and
#   2) because the caches themselves are threadsafe. Note that this will share these values
#   across filters and pipelines, though, as far as I understand it.
# See "Avoiding Concurrency Issues"
#   https://www.elastic.co/guide/en/logstash/current/plugins-filters-ruby.html#plugins-filters-ruby-concurrency
# Note that these calls are intended to be used during the "register" method.

$global_caches_hash = Concurrent::Hash.new
$global_ttl_caches_hash = Concurrent::Hash.new

def get_register_cache(
  cache_type,
  cache_size,
  getset_ignores_nil
)
  $global_caches_hash[cache_type] ||= LruReredux::ThreadSafeCache.new(cache_size, getset_ignores_nil)
end

def get_register_ttl_cache(
  cache_type,
  cache_size,
  cache_ttl,
  getset_ignores_nil
)
  $global_ttl_caches_hash[cache_type] ||= LruRedux::TTL::ThreadSafeCache.new(cache_size, cache_ttl, getset_ignores_nil)
end

##############################################################################################
# These global variables are used for generating performance profiling stats for
#   NetBox API calls and are not used by default
$method_timings_logging_thread_started = Concurrent::AtomicFixnum.new(0)
$method_timings = Concurrent::Hash.new { |h, k| h[k] = Concurrent::Array.new }
$method_timings_logging_thread = nil
$method_timings_logging_thread_running = false

$private_ip_subnets = {
  IPAddr.new("10.0.0.0/8")      => { network: IPAddr.new("10.0.0.0"), broadcast: IPAddr.new("10.255.255.255") },
  IPAddr.new("172.16.0.0/12")   => { network: IPAddr.new("172.16.0.0"), broadcast: IPAddr.new("172.31.255.255") },
  IPAddr.new("192.168.0.0/16")  => { network: IPAddr.new("192.168.0.0"), broadcast: IPAddr.new("192.168.255.255") },
  IPAddr.new("fc00::/7")        => { network: IPAddr.new("fc00::"), broadcast: IPAddr.new("fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff") }
}.freeze

##############################################################################################
class NetBoxConnLazy
  def initialize(
    url,
    token,
    debug
  )
    @object = nil
    @url = url
    @token = token
    @netboxConnDebug = debug
    @connected = false
  end

  def method_missing(method, *args, &block)

    puts "#{method}(#{args.map(&:inspect).join(', ')})" if @netboxConnDebug

    if $method_timings_logging_thread_running
      key = "#{method} #{args[0]}"
      key = key.to_sym
      start_time = Time.now
    end

    initialize_object unless @object
    result = @object.send(method, *args, &block)

    if $method_timings_logging_thread_running
      duration = (Time.now - start_time) * 1000
      $method_timings[key] << duration
    end

    @connected ||= !result.nil?
    result
  end

  def initialized?
    !@object.nil? && @connected
  end

  private

  def initialize_object
    @object = Faraday.new(@url) do |conn|
      conn.request :authorization, 'Token', @token
      conn.request :url_encoded
      conn.response :json, :parser_options => { :symbolize_names => true }
    end
    @connected = false
  end
end

##############################################################################################
def register(
  params
)
  # enable/disable based on script parameters and global environment variable
  _enabled_str = params["enabled"]
  _enabled_env = params["enabled_env"]
  if _enabled_str.nil? && !_enabled_env.nil?
    _enabled_str = ENV[_enabled_env]
  end
  @netbox_enabled = [1, true, '1', 'true', 't', 'on', 'enabled'].include?(_enabled_str.to_s.downcase)

  # source field containing lookup value
  @source = params["source"]

  # lookup type
  #   valid values are: ip_device, ip_prefix
  @lookup_type = params.fetch("lookup_type", "").to_sym

  # field containing site ID (or name) to use in queries for enrichment lookups and autopopulation
  @lookup_site_id = params["lookup_site_id"]
  if !@lookup_site_id.nil? && @lookup_site_id.empty?
    @lookup_site_id = nil
  end

  # fallback/default site value to use in queries for enrichment lookups and autopopulation,
  #   either specified directly or read from ENV
  @lookup_site = params["lookup_site"]
  _lookup_site_env = params["lookup_site_env"]
  if @lookup_site.nil? && !_lookup_site_env.nil?
    @lookup_site = ENV[_lookup_site_env]
  end
  if !@lookup_site.nil? && @lookup_site.empty?
    @lookup_site = nil
  end

  # whether or not to enrich service for ip_device
  _lookup_service_str = params["lookup_service"]
  _lookup_service_env = params["lookup_service_env"]
  if _lookup_service_str.nil? && !_lookup_service_env.nil?
    _lookup_service_str = ENV[_lookup_service_env]
  end
  @lookup_service = [1, true, '1', 'true', 't', 'on', 'enabled'].include?(_lookup_service_str.to_s.downcase)
  @lookup_service_port_source = params.fetch("lookup_service_port_source", "[destination][port]")

  # API parameters
  @page_size = params.fetch("page_size", 1000)

  # caching parameters (default cache size = 10000, default cache TTL = 300 seconds)
  _cache_size_val = params["cache_size"]
  _cache_size_env = params["cache_size_env"]
  if (!_cache_size_val.is_a?(Integer) || _cache_size_val <= 0) && !_cache_size_env.nil?
    _cache_size_val = Integer(ENV[_cache_size_env], exception: false)
  end
  if _cache_size_val.is_a?(Integer) && (_cache_size_val > 0)
    @cache_size = _cache_size_val
  else
    @cache_size = 10000
  end
  _cache_ttl_val = params["cache_ttl"]
  _cache_ttl_env = params["cache_ttl_env"]
  if (!_cache_ttl_val.is_a?(Integer) || _cache_ttl_val <= 0) && !_cache_ttl_env.nil?
    _cache_ttl_val = Integer(ENV[_cache_ttl_env], exception: false)
  end
  if _cache_ttl_val.is_a?(Integer) && (_cache_ttl_val > 0)
    @cache_ttl = _cache_ttl_val
  else
    @cache_ttl = 300
  end

  # target field to store looked-up value
  @target = params["target"]

  # for tagging events that go all the way through the filter
  @add_tag = params["add_tag"]
  _add_tag_env = params["add_tag_env"]
  if @add_tag.nil? && !_add_tag_env.nil?
    @add_tag = ENV[_add_tag_env]
  end
  if !@add_tag.nil? && @add_tag.empty?
    @add_tag = nil
  end

  # verbose - either specified directly or read from ENV via verbose_env
  #   false - store the "name" (fallback to "display") and "id" value(s) as @target.name and @target.id
  #             e.g., (@target is destination.segment) destination.segment.name => ["foobar"]
  #                                                    destination.segment.id => [123]
  #   true - store a hash of arrays *under* @target
  #             e.g., (@target is destination.segment) destination.segment.name => ["foobar"]
  #                                                    destination.segment.id => [123]
  #                                                    destination.segment.foo => ["bar"]
  #                                                    etc.
  _verbose_str = params["verbose"]
  _verbose_env = params["verbose_env"]
  if _verbose_str.nil? && !_verbose_env.nil?
    _verbose_str = ENV[_verbose_env]
  end
  @verbose = [1, true, '1', 'true', 't', 'on', 'enabled'].include?(_verbose_str.to_s.downcase)

  _debug_str = params["debug"]
  _debug_env = params["debug_env"]
  if _debug_str.nil? && !_debug_env.nil?
    _debug_str = ENV[_debug_env]
  end
  @debug_verbose = ['verbose', 'v', 'extra'].include?(_debug_str.to_s.downcase)
  @debug = (@debug_verbose || [1, true, '1', 'true', 't', 'on', 'enabled'].include?(_debug_str.to_s.downcase))

  _debug_timings_str = params["debug_timings"]
  _debug_timings_env = params["debug_timings_env"]
  if _debug_timings_str.nil? && !_debug_timings_env.nil?
    _debug_timings_str = ENV[_debug_timings_env]
  end
  @debug_timings = [1, true, '1', 'true', 't', 'on', 'enabled'].include?(_debug_timings_str.to_s.downcase)

  # connection URL for netbox
  # url, e.g., "https://netbox.example.org" or "http://netbox:8080"
  _netbox_url_str = params["netbox_url"].to_s.delete_suffix("/")
  _netbox_url_env = params["netbox_url_env"].to_s
  if _netbox_url_str.empty? && !_netbox_url_env.empty?
    _netbox_url_str = ENV[_netbox_url_env].to_s.delete_suffix("/")
  end
  if _netbox_url_str.empty?
    _netbox_url_str = "http://netbox:8080/netbox/api"
  end
  _netbox_url_obj = URI.parse(_netbox_url_str.end_with?('/api') ? _netbox_url_str : "#{_netbox_url_str}/api")
  @netbox_url = (_netbox_url_obj.port == _netbox_url_obj.default_port) ?
                  "#{_netbox_url_obj.scheme}://#{_netbox_url_obj.host}#{_netbox_url_obj.path}" :
                  "#{_netbox_url_obj.scheme}://#{_netbox_url_obj.host}:#{_netbox_url_obj.port}#{_netbox_url_obj.path}"
  @netbox_url_base = (_netbox_url_obj.port == _netbox_url_obj.default_port) ?
                       "#{_netbox_url_obj.scheme}://#{_netbox_url_obj.host}" :
                       "#{_netbox_url_obj.scheme}://#{_netbox_url_obj.host}:#{_netbox_url_obj.port}"
  @netbox_uri_suffix = _netbox_url_obj.path

  # connection token (either specified directly or read from ENV via netbox_token_env)
  @netbox_token = params["netbox_token"]
  _netbox_token_env = params["netbox_token_env"]
  if @netbox_token.nil? && !_netbox_token_env.nil?
    # could be something like "NETBOX_TOKEN;SUPERUSER_API_TOKEN", take first variable that evaluates
    @netbox_token = _netbox_token_env.split(/[;,:\s]+/).map { |env| ENV[env].to_s }.find { |val| val && !val.strip.empty? }
  end

  # hash of hashes, where key = site ID and value = hash of lookup types (from @lookup_type),
  #   each of which contains the respective looked-up values
  @site_lookup_types_hash = get_register_cache(:site_lookup_types_hash, 256, true)
  @lookup_cache_size = params.fetch("lookup_cache_size", 512)

  # these are used for autopopulation only, not lookup/enrichment

  # autopopulate - either specified directly or read from ENV via autopopulate_env
  #   false - do not autopopulate netbox inventory when uninventoried devices are observed
  #   true - autopopulate netbox inventory when uninventoried devices are observed (not recommended)
  #
  # For now this is only done for devices/virtual machines, not for services or network segments.
  _autopopulate_str = params["autopopulate"]
  _autopopulate_env = params["autopopulate_env"]
  if _autopopulate_str.nil? && !_autopopulate_env.nil?
    _autopopulate_str = ENV[_autopopulate_env]
  end
  @autopopulate = [1, true, '1', 'true', 't', 'on', 'enabled'].include?(_autopopulate_str.to_s.downcase)

  # fields for device autopopulation
  @source_hostname = params["source_hostname"]
  @source_oui = params["source_oui"]
  @source_mac = params["source_mac"]
  @source_segment = params["source_segment"]
  @default_status = params.fetch("default_status", "active").to_sym

  # default manufacturer, role and device type if not specified, either specified directly or read from ENVs
  @default_manuf = params["default_manuf"]
  _default_manuf_env = params["default_manuf_env"]
  if @default_manuf.nil? && !_default_manuf_env.nil?
    @default_manuf = ENV[_default_manuf_env]
  end
  if !@default_manuf.nil? && @default_manuf.empty?
    @default_manuf = nil
  end

  _vendor_oui_map_path = params.fetch("vendor_oui_map_path", "/etc/vendor_macs.yaml")
  if File.exist?(_vendor_oui_map_path)
    @macarray = Array.new
    psych_load_yaml(_vendor_oui_map_path).each do |mac|
      @macarray.push([mac_string_to_integer(mac['low']), mac_string_to_integer(mac['high']), mac['name']])
    end
    # Array.bsearch only works on a sorted array
    @macarray.sort_by! { |k| [k[0], k[1]]}
  else
    @macarray = nil
  end
  @macregex = Regexp.new(/\A([0-9a-fA-F]{2}[-:.]){5}([0-9a-fA-F]{2})\z/)

  _vm_oui_map_path = params.fetch("vm_oui_map_path", "/etc/vm_macs.yaml")
  if File.exist?(_vm_oui_map_path)
    @vm_namesarray = Set.new
    psych_load_yaml(_vm_oui_map_path).each do |mac|
      @vm_namesarray.add(mac['name'].to_s.downcase)
    end
  else
    @vm_namesarray = Set[ "pcs computer systems gmbh",
                          "proxmox server solutions gmbh",
                          "vmware, inc.",
                          "xensource, inc." ]
  end

  @default_dtype = params["default_dtype"]
  _default_dtype_env = params["default_dtype_env"]
  if @default_dtype.nil? && !_default_dtype_env.nil?
    @default_dtype = ENV[_default_dtype_env]
  end
  if !@default_dtype.nil? && @default_dtype.empty?
    @default_dtype = nil
  end

  @default_role = params["default_role"]
  _default_role_env = params["default_role_env"]
  if @default_role.nil? && !_default_role_env.nil?
    @default_role = ENV[_default_role_env]
  end
  if !@default_role.nil? && @default_role.empty?
    @default_role = nil
  end

  # threshold for fuzzy string matching (for manufacturer, etc.)
  _autopopulate_fuzzy_threshold_str = params["autopopulate_fuzzy_threshold"]
  _autopopulate_fuzzy_threshold_str_env = params["autopopulate_fuzzy_threshold_env"]
  if _autopopulate_fuzzy_threshold_str.nil? && !_autopopulate_fuzzy_threshold_str_env.nil?
    _autopopulate_fuzzy_threshold_str = ENV[_autopopulate_fuzzy_threshold_str_env]
  end
  if _autopopulate_fuzzy_threshold_str.nil? || _autopopulate_fuzzy_threshold_str.empty?
    @autopopulate_fuzzy_threshold = 0.95
  else
    @autopopulate_fuzzy_threshold = _autopopulate_fuzzy_threshold_str.to_f
  end

  # if the manufacturer is not found, should we create one or use @default_manuf?
  _autopopulate_create_manuf_str = params["autopopulate_create_manuf"]
  _autopopulate_create_manuf_env = params["autopopulate_create_manuf_env"]
  if _autopopulate_create_manuf_str.nil? && !_autopopulate_create_manuf_env.nil?
    _autopopulate_create_manuf_str = ENV[_autopopulate_create_manuf_env]
  end
  @autopopulate_create_manuf = [1, true, '1', 'true', 't', 'on', 'enabled'].include?(_autopopulate_create_manuf_str.to_s.downcase)

  # if the prefix is not found, should we create one?
  _autopopulate_create_prefix_str = params["auto_prefix"]
  _autopopulate_create_prefix_env = params["auto_prefix_env"]
  if _autopopulate_create_prefix_str.nil? && !_autopopulate_create_prefix_env.nil?
    _autopopulate_create_prefix_str = ENV[_autopopulate_create_prefix_env]
  end
  @autopopulate_create_prefix = [1, true, '1', 'true', 't', 'on', 'enabled'].include?(_autopopulate_create_prefix_str.to_s.downcase)

  # case-insensitive hash of OUIs (https://standards-oui.ieee.org/) to Manufacturers (https://demo.netbox.dev/static/docs/core-functionality/device-types/)
  @manuf_hash = get_register_ttl_cache(:manuf_hash, params.fetch("manuf_cache_size", 4096), @cache_ttl, true)

  # case-insensitive hash of role names to IDs
  @role_hash = get_register_ttl_cache(:role_hash, params.fetch("role_cache_size", 512), @cache_ttl, true)

  # case-insensitive hash of site names to site IDs
  @site_name_hash = get_register_ttl_cache(:site_name_hash, params.fetch("site_cache_size", 256), @cache_ttl, true)

  # hash of site IDs to site objects
  @site_id_hash = get_register_ttl_cache(:site_id_hash, params.fetch("site_cache_size", 256), @cache_ttl, true)

  # end of autopopulation arguments

  # used for massaging OUI/manufacturer names for matching
  @name_cleaning_patterns = [ /\ba[sbg]\b/,
                              /\b(beijing|shenzhen)\b/,
                              /\bbv\b/,
                              /\bco(rp(oration|orate)?)?\b/,
                              /\b(computer|network|electronic|solution|system)s?\b/,
                              /\bglobal\b/,
                              /\bgmbh\b/,
                              /\binc(orporated)?\b/,
                              /\bint(ernationa)?l?\b/,
                              /\bkft\b/,
                              /\blimi?ted\b/,
                              /\bllc\b/,
                              /\b(co)?ltda?\b/,
                              /\bpt[ey]\b/,
                              /\bpvt\b/,
                              /\boo\b/,
                              /\bsa\b/,
                              /\bsr[ol]s?\b/,
                              /\btech(nolog(y|ie|iya)s?)?\b/ ].freeze

  @nb_headers = { 'Content-Type': 'application/json' }.freeze

  @device_tag_autopopulated = { 'slug': 'malcolm-autopopulated' }.freeze
  # for ip_device hash lookups, if a device is pulled out that has one of these tags
  #   it should be *updated* instead of just created. this allows us to create even less-fleshed
  #   out device entries from things like DNS entries but then give more information (like
  #   manufacturer) later on when actual traffic is observed. these values should match
  #   what's in netbox/preload/tags.yml
  @device_tag_manufacturer_unknown = { 'slug': 'manufacturer-unknown' }.freeze
  @device_tag_hostname_unknown = { 'slug': 'hostname-unknown' }.freeze

  @virtual_machine_device_type_name = "Virtual Machine".freeze

  if @debug_timings && ($method_timings_logging_thread_started.value == 0) && $method_timings_logging_thread_started.compare_and_set(0, 1)
     $method_timings = Concurrent::Hash.new { |h, k| h[k] = Concurrent::Array.new }
     $method_timings_logging_thread = Thread.new { log_method_timings_thread_proc }
     $method_timings_logging_thread_running = true
   end

  # make sure required tags exist before starting up
  _tmp_nb_conn = NetBoxConnLazy.new(@netbox_url, @netbox_token, @debug_verbose)
  [
    [{ 'name' => 'Autopopulated', 'slug' => 'malcolm-autopopulated', 'color' => 'add8e6' }],
    [{ 'name' => 'Manufacturer Unknown', 'slug' => 'manufacturer-unknown', 'color' => 'd3d3d3' }],
    [{ 'name' => 'Hostname Unknown', 'slug' => 'hostname-unknown', 'color' => 'd3d3d3'}]
  ].each do |item|
    begin
      _tmp_response = _tmp_nb_conn.post('extras/tags/', item.to_json, @nb_headers)
    rescue Faraday::Error => e
      # Do nothing (ignore errors)
    end
  end
end

##############################################################################################
def log_method_timings_thread_proc
  while $method_timings_logging_thread_running
    sleep 60
    puts "Method Execution Timings ---------------- :"
    $method_timings.each do |method, times|
      total_time = times.empty? ? 0 : times.sum
      avg_time = times.empty? ? 0 : total_time / times.size
      puts "#{method}: total #{total_time.round(2)} ms, avg #{avg_time.round(2)} ms over #{times.size} calls"
    end
  end
end

##############################################################################################
def getset_with_tracking(cache, key)
  cache_hit = true
  result = cache.getset(key) do
    cache_hit = false
    yield
  end
  { result: result, cache_hit: cache_hit }
end

##############################################################################################
def assignable_private_ip?(ip)
  ipaddr = if ip.is_a?(IPAddr)
             ip
           else
             begin
               IPAddr.new(ip)
             rescue
               nil
             end
           end
  return false if ipaddr.nil?

  $private_ip_subnets.find do |subnet, addresses|
    if subnet.include?(ipaddr)
      return ipaddr != addresses[:network] && ipaddr != addresses[:broadcast]
    end
  end

  false
end

##############################################################################################
def filter(
  event
)
  _key = event.get("#{@source}")
  if (not @netbox_enabled) || @lookup_type.nil? || @lookup_type.empty? || _key.nil? || _key.empty?
    return [event]
  end

  # site *must* be specified from the VERY TOP, either explicitly by ID (or name) in lookup_site_id
  #   or via the fallback @lookup_site value. If we can't get (or create) the site, we can't determine which
  #   hashes to look up the _key by @lookup_type in, nor where to autopopulate, etc.
  _lookup_site_id_str = @lookup_site_id.nil? ? nil : event.get("#{@lookup_site_id}").to_s
  if (_lookup_site_id_str == "0")
    # A site ID of 0 is a way to shortcut and say "skip netbox enrichment completely" on a per-event basis.
    #   As the "default" site ID is 1, this will only be a 0 if it's explicitly set as such.
    return [event]
  end
  _lookup_site_name_str =  (@lookup_site.nil? || @lookup_site.empty?) ? "default" : @lookup_site
  _lookup_site_obj = lookup_or_create_site(_lookup_site_id_str, _lookup_site_name_str, nil)
  if _lookup_site_obj.is_a?(Hash) && ((_lookup_site_id = _lookup_site_obj.fetch(:id, 0).to_i) > 0)
    _site_lookups_hash = @site_lookup_types_hash.getset(_lookup_site_id){ LruReredux::ThreadSafeCache.new(@lookup_cache_size, true) }
    _lookup_hash = _site_lookups_hash.getset(@lookup_type){ LruReredux::TTL::ThreadSafeCache.new(@cache_size, @cache_ttl, true) }
    puts "netbox_enrich.filter: found site (#{_lookup_site_id_str}, #{_lookup_site_name_str}): #{JSON.generate(_lookup_site_obj)}" if @debug_verbose
  else
    puts "netbox_enrich.filter: unable to lookup site (#{_lookup_site_id_str}, #{_lookup_site_name_str})" if @debug
    return [event]
  end

  _result_set = false
  _discovered_flag = false
  _netbox_queried = false

  # _key might be an array of IP addresses, but we're only going to set the first _result into @target.
  #    this is still useful, though as autopopulation may happen for multiple IPs even if we only
  #    store the result of the first one found
  if !_key.is_a?(Array) then
    _newKey = Array.new
    _newKey.push(_key) unless _key.nil?
    _key = _newKey
  end
  # _private_ips stores IPAddr representations of IP strings for private IP addresses
  _private_ips = Array.new

  _key.each do |ip_key|

    _lookup_tracking_result = getset_with_tracking(_lookup_hash, ip_key) do
      netbox_lookup(event: event, ip_key: ip_key, site_id: _lookup_site_id)
    end
    if _lookup_tracking_result[:result]
      _result, _key_ip, _nb_queried = _lookup_tracking_result[:result].dup
    else
      _result, _key_ip, _nb_queried = nil, nil, false
    end
    _private_ips.push(_key_ip) if assignable_private_ip?(_key_ip)
    _netbox_queried ||= _nb_queried unless _lookup_tracking_result[:cache_hit]

    if !_result.nil? && !_result.empty?

      if _lookup_tracking_result[:cache_hit]
        # it can't have been "discovered" if it was already in the cache
        _result.delete(:discovered)
      else
        _result[:discovered] = _result[:discovered]&.any? if _result[:discovered].is_a?(Array)
        _result.delete(:discovered) unless _result[:discovered]
        _discovered_flag ||= _result.fetch(:discovered, false)
      end

      puts('netbox_enrich.filter(%{lookup_type}: %{lookup_key} @ %{site}) success: %{result}' % {
            lookup_type: @lookup_type,
            lookup_key: ip_key,
            site: _lookup_site_id,
            result: JSON.generate(_result) }) if @debug_verbose

      # we've done a lookup and got (or autopopulated) our answer, however, if this is a device lookup and
      #   either the hostname-unknown or manufacturer-unknown is set, we should see if we can update it
      if (_tags = _result.fetch(:tags, nil)) &&
         @autopopulate &&
         (@lookup_type == :ip_device) &&
         _tags.is_a?(Array) &&
         _tags.flatten! &&
         _tags.all? { |item| item.is_a?(Hash) } &&
         _tags.any? {|tag| tag[:slug] == @device_tag_autopopulated[:slug]}
      then
        _updated_result = nil
        _autopopulate_hostname = event.get("#{@source_hostname}").to_s
        _autopopulate_mac = event.get("#{@source_mac}").to_s.downcase
        _autopopulate_oui = event.get("#{@source_oui}").to_s
        if ((_tags.any? {|tag| tag[:slug] == @device_tag_hostname_unknown[:slug]} &&
             (!_autopopulate_hostname.empty? && !_autopopulate_hostname.end_with?('.in-addr.arpa'))) ||
            (_tags.any? {|tag| tag[:slug] == @device_tag_manufacturer_unknown[:slug]} &&
              ((!_autopopulate_mac.empty? && (_autopopulate_mac != 'ff:ff:ff:ff:ff:ff') && (_autopopulate_mac != '00:00:00:00:00:00')) ||
               !_autopopulate_oui.empty?)))
        then
          # the hostname-unknown tag is set, but we appear to have a hostname
          #   from the event. we need to update the record in netbox (set the new hostname
          #   from this value and remove the tag) and in the result
          # OR
          # the manufacturer-unknown tag is set, but we appear to have an OUI or MAC address
          #   from the event. we need to update the record in netbox (determine the manufacturer
          #   from this value and remove the tag) and in the result
          _updated_result, _key_ip, _nb_queried = netbox_lookup(:event=>event, :ip_key=>ip_key, :site_id=>_lookup_site_id, :previous_result=>_result)
          puts('filter tried to patch %{name} (site %{site}) for "%{tags}" ("%{host}", "%{mac}", "%{oui}"): %{result}' % {
                name: ip_key,
                site: _lookup_site_id,
                tags: _tags.map{ |hash| hash[:slug] }.join('|'),
                host: _autopopulate_hostname,
                mac: _autopopulate_mac,
                oui: _autopopulate_oui,
                result: JSON.generate(_updated_result) }) if @debug
        end
        _lookup_hash[ip_key] = (_result = _updated_result) if _updated_result
      end
      _result.delete(:tags)

      if _result.has_key?(:url) && !_result[:url]&.empty?
        _result[:url].map! { |u| u.delete_prefix(@netbox_url_base).gsub('/api/', '/') }
        if (@lookup_type == :ip_device) &&
           (!_result.has_key?(:device_type) || _result[:device_type]&.empty?) &&
           _result[:url].any? { |u| u.include? "virtual-machines" }
        then
          _result[:device_type] = [ @virtual_machine_device_type_name ]
        end
      end
    else
      puts "netbox_enrich.filter(#{@lookup_type}: #{ip_key} @ #{_lookup_site_id}) failed" if @debug_verbose
    end

    unless _result_set || _result.nil? || _result.empty? || @target.nil? || @target.empty?
      event.set("#{@target}", _result)
      _result_set = true
    end
  end # _key.each do |ip_key|

  if (@lookup_type == :ip_device) &&
     (_discovered_flag || (_netbox_queried && !_result_set)) &&
     !_private_ips.empty? &&
     !@target.nil? &&
     !@target.empty?
  then
    # no result found, this device should be marked as "uninventoried"
    _result = _result_set ? event.get("#{@target}") : Hash.new
    if _result.is_a?(Hash)
      _result[:uninventoried] = true
      event.set("#{@target}", _result)
    end
  end

  unless _private_ips.empty? || @add_tag.nil? || @add_tag.empty?
    _tags = event.get('[tags]')
    if !_tags.is_a?(Array) then
      _newTags = Array.new
      _newTags.push(_tags) unless _tags.nil? || _tags.empty?
      _tags = _newTags
    end
    if !_tags.include? @add_tag
      _tags.push(@add_tag)
      event.set("[tags]", _tags)
    end
  end

  [event]
end

def mac_string_to_integer(
  string
)
  string.tr('.:-','').to_i(16)
end

def mac_to_oui_lookup(
  mac
)
  _oui = nil

  case mac
  when String
    if @macregex.match?(mac)
      _macint = mac_string_to_integer(mac)
      _vendor = @macarray.bsearch{ |_vendormac| (_macint < _vendormac[0]) ? -1 : ((_macint > _vendormac[1]) ? 1 : 0)}
      _oui = _vendor[2] unless _vendor.nil?
    end # mac matches @macregex
  when Array
    mac.each do |_addr|
      if @macregex.match?(_addr)
        _macint = mac_string_to_integer(_addr)
        _vendor = @macarray.bsearch{ |_vendormac| (_macint < _vendormac[0]) ? -1 : ((_macint > _vendormac[1]) ? 1 : 0)}
        if !_vendor.nil?
          _oui = _vendor[2]
          break
        end # !_vendor.nil?
      end # _addr matches @macregex
    end # mac.each do
  end # case statement mac String vs. Array

  _oui
end

def psych_load_yaml(
  filename
)
  parser = Psych::Parser.new(Psych::TreeBuilder.new)
  parser.code_point_limit = 64*1024*1024
  parser.parse(IO.read(filename, :mode => 'r:bom|utf-8'))
  yaml_obj = Psych::Visitors::ToRuby.create().accept(parser.handler.root)
  if yaml_obj.is_a?(Array) && (yaml_obj.length() == 1)
    yaml_obj.first
  else
    yaml_obj
  end
end

def collect_values(
  hashes
)
  # https://stackoverflow.com/q/5490952
  hashes.reduce({}){ |h, pairs| pairs.each { |k,v| (h[k] ||= []) << v}; h }
end

def crush(
  thing
)
  if thing.is_a?(Array)
    thing.each_with_object([]) do |v, a|
      v = crush(v)
      a << v unless [nil, [], {}, "", "Unspecified", "unspecified"].include?(v)
    end
  elsif thing.is_a?(Hash)
    thing.each_with_object({}) do |(k,v), h|
      v = crush(v)
      h[k] = v unless ([nil, [], {}, "", "Unspecified", "unspecified"].include?(v) || (k == :url))
    end
  else
    thing
  end
end

def clean_manuf_string(
  val
)
    # 0. downcase
    # 1. replace commas with spaces
    # 2. remove all punctuation (except parens)
    # 3. squash whitespace down to one space
    # 4. remove each of @name_cleaning_patterns (LLC, LTD, Inc., etc.)
    # 5. remove all punctuation (even parens)
    # 6. strip leading and trailing spaces
    new_val = val.downcase.gsub(',', ' ').gsub(/[^\(\)A-Za-z0-9\s]/, '').gsub(/\s+/, ' ')
    @name_cleaning_patterns.each do |pat|
      new_val = new_val.gsub(pat, '')
    end
    new_val = new_val.gsub(/[^A-Za-z0-9\s]/, '').gsub(/\s+/, ' ').lstrip.rstrip
    new_val
end

def shorten_string(
  val
)
  if val.length > 64
    "#{val[0, 30]}...#{val[-30, 30]}"
  else
    val
  end
end

def lookup_or_create_site(
  site_id,
  site_name,
  nb
)
  _result_site_obj = nil
  _site_id_str = site_id.to_s
  _site_name_str = site_name.to_s
  _nb_to_use = nb

  # if the ID was specified explicitly, use that first to look up the site
  if (!_site_id_str.empty?) && (_site_id_str.scan(/\D/).empty?) && (_site_id_str.to_i > 0) then
    _site_id_int = _site_id_str.to_i
    _result_site_obj = @site_id_hash.getset(_site_id_int) {
      begin
        _site = nil

        # this shouldn't be too often, once the hash gets populated
        _nb_to_use = NetBoxConnLazy.new(@netbox_url, @netbox_token, @debug_verbose) if _nb_to_use.nil?

        # look it up by ID
        _query = { :offset => 0,
                   :limit => 1,
                   :id => _site_id_int }
        if (_sites_response = _nb_to_use.get('dcim/sites/', _query).body) &&
           _sites_response.is_a?(Hash) &&
           (_tmp_sites = _sites_response.fetch(:results, [])) &&
           (_tmp_sites.length() > 0)
        then
           _site = _tmp_sites.first
        elsif @debug
          puts('lookup_or_create_site (%{id}): _sites_response: %{result}' % { id: _site_id_str, result: JSON.generate(_sites_response) })
        end

      rescue Faraday::Error => e
        # give up aka do nothing
        puts "lookup_or_create_site (#{_site_id_str}): #{e.message}" if @debug
      end

      _site
    }.dup
  end

  # if the site ID wasn't specified but the name was, either look up or create it by name
  if _result_site_obj.nil? && (!_site_id_str.empty? || !_site_name_str.empty?) then
    _site_name_key_str = (!_site_id_str.empty? && !_site_id_str.scan(/\D/).empty?) ? _site_id_str : _site_name_str
    _result_site_id = @site_name_hash.getset(_site_name_key_str) {
      begin
        _site = nil
        _site_id = 0

        # this shouldn't be too often, once the hash gets populated
        _nb_to_use = NetBoxConnLazy.new(@netbox_url, @netbox_token, @debug_verbose) if _nb_to_use.nil?

        # try to look it up by name
        _query = { :offset => 0,
                   :limit => 1,
                   :name => _site_name_key_str }
        if (_sites_response = _nb_to_use.get('dcim/sites/', _query).body) &&
           _sites_response.is_a?(Hash) &&
           (_tmp_sites = _sites_response.fetch(:results, [])) &&
           (_tmp_sites.length() > 0)
        then
           _site = _tmp_sites.first
        elsif @debug
          puts('lookup_or_create_site (%{name}): _sites_response: %{result}' % { name: _site_name_key_str, result: JSON.generate(_sites_response) })
        end

        if _site.is_a?(Hash)
          _site_id = _site.fetch(:id, 0)
        elsif @autopopulate
          # the device site is not found, create it
          _site_data = { :name => _site_name_key_str,
                         :slug => _site_name_key_str.to_url,
                         :status => "active" }
          if (_site_create_response = _nb_to_use.post('dcim/sites/', _site_data.to_json, @nb_headers).body) &&
             _site_create_response.is_a?(Hash) &&
             _site_create_response.has_key?(:id)
          then
             _site_id = _site_create_response.fetch(:id, 0)
          elsif @debug
            puts('lookup_or_create_site (%{name}): _site_create_response: %{result}' % { name: _site_name_key_str, result: JSON.generate(_site_create_response) })
          end
        end

      rescue Faraday::Error => e
        # give up aka do nothing
        puts "lookup_or_create_site (#{_site_name_key_str}): #{e.message}" if @debug
      end

      _site_id
    }
    if (_result_site_id.to_i > 0) then
      # we got name -> ID in site_name_hash, now recursively call to make sure ID -> obj ends up in @site_id_hash
      _result_site_obj = lookup_or_create_site(_result_site_id, '', _nb_to_use)
    end
  end

  _result_site_obj
end

def lookup_manuf(
  oui,
  nb
)
  if !oui.to_s.empty?
    @manuf_hash.getset(oui) {
      _fuzzy_matcher = FuzzyStringMatch::JaroWinkler.create( :pure )
      _oui_cleaned = clean_manuf_string(oui.to_s)
      _manufs = Array.new
      # fetch the manufacturers to do the comparison. this is a lot of work
      # and not terribly fast but once the hash it populated it shouldn't happen too often
      _query = { :offset => 0,
                 :limit => @page_size }
      begin
        while true do
          if (_manufs_response = nb.get('dcim/manufacturers/', _query).body) &&
             _manufs_response.is_a?(Hash)
          then
            _tmp_manufs = _manufs_response.fetch(:results, [])
            _tmp_manufs.each do |_manuf|
              _tmp_name = _manuf.fetch(:name, _manuf.fetch(:display, nil))
              _tmp_distance = _fuzzy_matcher.getDistance(clean_manuf_string(_tmp_name.to_s), _oui_cleaned)
              if (_tmp_distance >= @autopopulate_fuzzy_threshold) then
                _manufs << { :name => _tmp_name,
                             :id => _manuf.fetch(:id, nil),
                             :url => _manuf.fetch(:url, nil),
                             :match => _tmp_distance,
                             :vm => false }
              end
            end
            _query[:offset] += _tmp_manufs.length()
            break unless (_tmp_manufs.length() >= @page_size)
          else
            break
          end
        end
      rescue Faraday::Error => e
        # give up aka do nothing
        puts "lookup_manuf (#{oui}): #{e.message}" if @debug
      end
      # return the manuf with the highest match
      # puts('0. %{key}: %{matches}' % { key: _autopopulate_oui_cleaned, matches: JSON.generate(_manufs) })-]
      !_manufs&.empty? ? _manufs.max_by{|k| k[:match] } : nil
    }.dup
  else
    nil
  end
end

def lookup_or_create_manuf_and_dtype(
  oui,
  default_manuf,
  default_dtype,
  nb
)
  _oui = oui
  _dtype = nil
  _manuf = nil

  begin
    # match/look up manufacturer based on OUI
    if !_oui.nil? && !_oui.empty?
      _oui = _oui.first() unless !_oui.is_a?(Array)
      # does it look like a VM or a regular device?
      if @vm_namesarray.include?(_oui.downcase)
        # looks like this is probably a virtual machine
        _manuf = { :name => _oui,
                   :match => 1.0,
                   :vm => true,
                   :id => nil }
      else
        # looks like this is not a virtual machine (or we can't tell) so assume it's a regular device
        _manuf = lookup_manuf(_oui, nb)
      end # virtual machine vs. regular device
    end # oui specified

    # puts('1. %{key}: %{found}' % { key: oui, found: JSON.generate(_manuf) })
    if !_manuf.is_a?(Hash)
      # no match was found at ANY match level (empty database or no OUI specified), set default ("unspecified") manufacturer
      _manuf = { :name => (@autopopulate_create_manuf && !_oui.nil? && !_oui.empty?) ? _oui : default_manuf,
                 :match => 0.0,
                 :vm => false,
                 :id => nil}
    end
    # puts('2. %{key}: %{found}' % { key: _oui, found: JSON.generate(_manuf) })

    if !_manuf[:vm]

      if !_manuf.fetch(:id, nil)&.nonzero?
        # the manufacturer was default (not found) so look it up first
        _query = { :offset => 0,
                   :limit => 1,
                   :name => _manuf[:name] }
        if (_manufs_response = nb.get('dcim/manufacturers/', _query).body) &&
           _manufs_response.is_a?(Hash) &&
           (_tmp_manufs = _manufs_response.fetch(:results, [])) &&
           (_tmp_manufs.length() > 0)
        then
           _manuf[:id] = _tmp_manufs.first.fetch(:id, nil)
           _manuf[:match] = 1.0
        end
      end
      # puts('3. %{key}: %{found}' % { key: _oui, found: JSON.generate(_manuf) })

      if !_manuf.fetch(:id, nil)&.nonzero?
        # the manufacturer is still not found, create it
        _manuf_data = { :name => _manuf[:name],
                        :tags => [ @device_tag_autopopulated ],
                        :slug => _manuf[:name].to_url }
        if (_manuf_create_response = nb.post('dcim/manufacturers/', _manuf_data.to_json, @nb_headers).body) &&
           _manuf_create_response.is_a?(Hash)
        then
           _manuf[:id] = _manuf_create_response.fetch(:id, nil)
           _manuf[:match] = 1.0
        elsif @debug
          puts('lookup_or_create_manuf_and_dtype (%{name}): _manuf_create_response: %{result}' % { name: _manuf[:name], result: JSON.generate(_manuf_create_response) })
        end
        # puts('4. %{key}: %{created}' % { key: _manuf, created: JSON.generate(_manuf_create_response) })
      end

      # at this point we *must* have the manufacturer ID
      if _manuf.fetch(:id, nil)&.nonzero?

        # make sure the desired device type also exists, look it up first
        _query = { :offset => 0,
                   :limit => 1,
                   :manufacturer_id => _manuf[:id],
                   :model => default_dtype }
        if (_dtypes_response = nb.get('dcim/device-types/', _query).body) &&
           _dtypes_response.is_a?(Hash) &&
           (_tmp_dtypes = _dtypes_response.fetch(:results, [])) &&
           (_tmp_dtypes.length() > 0)
        then
           _dtype = _tmp_dtypes.first
        end

        if _dtype.nil?
          # the device type is not found, create it
          _dtype_data = { :manufacturer => _manuf[:id],
                          :model => default_dtype,
                          :tags => [ @device_tag_autopopulated ],
                          :slug => default_dtype.to_url }
          if (_dtype_create_response = nb.post('dcim/device-types/', _dtype_data.to_json, @nb_headers).body) &&
             _dtype_create_response.is_a?(Hash) &&
             _dtype_create_response.has_key?(:id)
          then
             _dtype = _dtype_create_response
          elsif @debug
            puts('lookup_or_create_manuf_and_dtype (%{name}: _dtype_create_response: %{result}' % { name: default_dtype, result: JSON.generate(_dtype_create_response) })
          end
        end

      end # _manuf :id check
    end # _manuf is not a VM

  rescue Faraday::Error => e
    # give up aka do nothing
    puts "lookup_or_create_manuf_and_dtype (#{oui}): #{e.message}" if @debug
  end

  return _dtype, _manuf

end # def lookup_or_create_manuf_and_dtype

def lookup_prefixes(
  ip_str,
  site_id,
  nb
)
  prefixes = Array.new

  _query = { :contains => ip_str,
             :offset => 0,
             :limit => @page_size }
  if (site_id.is_a?(Integer) && (site_id > 0))
    _query[:scope_type] = "dcim.site"
    _query[:scope_id] = site_id
  end
  begin
    while true do
      if (_prefixes_response = nb.get('ipam/prefixes/', _query).body) &&
         _prefixes_response.is_a?(Hash)
      then
        _tmp_prefixes = _prefixes_response.fetch(:results, [])
        _tmp_prefixes.each do |p|
          # non-verbose output is flatter with just names { :name => "name", :id => "id", ... }
          # if verbose, include entire object as :details
          _prefixName = p.fetch(:description, nil)
          if _prefixName.nil? || _prefixName.empty?
            _prefixName = p.fetch(:display, p.fetch(:prefix, nil))
          end
          prefixes << { :name => _prefixName,
                        :id => p.fetch(:id, nil),
                        :site => ((_site = p.fetch(:site, nil)) && _site&.has_key?(:name)) ? _site[:name] : _site&.fetch(:display, nil),
                        :tenant => ((_tenant = p.fetch(:tenant, nil)) && _tenant&.has_key?(:name)) ? _tenant[:name] : _tenant&.fetch(:display, nil),
                        :url => p.fetch(:url, nil),
                        :tags => p.fetch(:tags, nil),
                        :details => @verbose ? p : nil }
        end
        _query[:offset] += _tmp_prefixes.length()
        break unless (_tmp_prefixes.length() >= @page_size)
      else
        break
      end
    end
  rescue Faraday::Error => e
    # give up aka do nothing
    puts "lookup_prefixes (#{ip_str}, #{site_id}): #{e.message}" if @debug
  end

  prefixes
end

def lookup_or_create_role(
  role_name,
  nb
)
  if !role_name.to_s.empty?
    @role_hash.getset(role_name) {
      begin
        _role = nil

        # look it up first
        _query = { :offset => 0,
                   :limit => 1,
                   :name => role_name }
        if (_roles_response = nb.get('dcim/device-roles/', _query).body) &&
           _roles_response.is_a?(Hash) &&
           (_tmp_roles = _roles_response.fetch(:results, [])) &&
           (_tmp_roles.length() > 0)
        then
           _role = _tmp_roles.first
        end

        if _role.nil?
          # the role is not found, create it
          _role_data = { :name => role_name,
                         :slug => role_name.to_url,
                         :color => "d3d3d3" }
          if (_role_create_response = nb.post('dcim/device-roles/', _role_data.to_json, @nb_headers).body) &&
             _role_create_response.is_a?(Hash) &&
             _role_create_response.has_key?(:id)
          then
             _role = _role_create_response
          elsif @debug
            puts('lookup_or_create_role (%{name}): _role_create_response: %{result}' % { name: role_name, result: JSON.generate(_role_create_response) })
          end
        end

      rescue Faraday::Error => e
        # give up aka do nothing
        puts "lookup_or_create_role (#{role_name}): #{e.message}" if @debug
      end
      _role
    }.dup
  else
    nil
  end
end

def lookup_devices(
  ip_str,
  site_id,
  lookup_service_port,
  url_base,
  url_suffix,
  nb
)
  _devices = Array.new
  _query = { :address => ip_str,
             :offset => 0,
             :limit => @page_size }
  begin
    while true do
      # query all matching IP addresses, but only return devices where the site matches
      if (_ip_addresses_response = nb.get('ipam/ip-addresses/', _query).body) &&
         _ip_addresses_response.is_a?(Hash)
      then
        _tmp_ip_addresses = _ip_addresses_response.fetch(:results, [])
        _tmp_ip_addresses.each do |i|
          _is_device = nil
          if (_obj = i.fetch(:assigned_object, nil)) &&
             ((_device_obj = _obj.fetch(:device, nil)) ||
              (_virtualized_obj = _obj.fetch(:virtual_machine, nil)))
          then
            _is_device = !_device_obj.nil?
            _device = _is_device ? _device_obj : _virtualized_obj
            # if we can, follow the :assigned_object's "full" device URL to get more information
            _device = (_device.has_key?(:url) && (_full_device = nb.get(_device[:url].delete_prefix(url_base).delete_prefix(url_suffix).delete_prefix("/")).body)) ? _full_device : _device
            _device_site_obj = _device.fetch(:site, nil)
            if ((_device_site_obj&.fetch(:id, 0)).to_i == site_id.to_i)
              _device_id = _device.fetch(:id, nil)
              puts('lookup_devices(%{lookup_key} @ %{site}) candidate %{device_id} match: %{device}' % {
                    lookup_key: ip_str,
                    site: site_id,
                    device_id: _device_id,
                    device: JSON.generate(_device) }) if @debug_verbose
            else
              puts('lookup_devices(%{lookup_key} @ %{site}) candidate mismatch: %{device}' % {
                    lookup_key: ip_str,
                    site: site_id,
                    device: JSON.generate(_device) }) if @debug_verbose
              next
            end
            # look up service if requested (based on device/vm found and service port)
            if (lookup_service_port > 0)
              _services = Array.new
              _service_query = { (_is_device ? :device_id : :virtual_machine_id) => _device_id, :port => lookup_service_port, :offset => 0, :limit => @page_size }
              while true do
                if (_services_response = nb.get('ipam/services/', _service_query).body) &&
                   _services_response.is_a?(Hash)
                then
                  _tmp_services = _services_response.fetch(:results, [])
                  _services.unshift(*_tmp_services) unless _tmp_services.nil? || _tmp_services.empty?
                  _service_query[:offset] += _tmp_services.length()
                  break unless (_tmp_services.length() >= @page_size)
                else
                  break
                end
              end
              _device[:service] = _services
            end
            # non-verbose output is flatter with just names { :name => "name", :id => "id", ... }
            # if verbose, include entire object as :details
            _devices << { :name => _device.fetch(:name, _device.fetch(:display, nil)),
                          :id => _device_id,
                          :url => _device.fetch(:url, nil),
                          :tags => _device.fetch(:tags, nil),
                          :service => _device.fetch(:service, []).map {|s| s.fetch(:name, s.fetch(:display, nil)) },
                          :site => _device_site_obj&.fetch(:name, _device_site_obj&.fetch(:display, nil)),
                          :role => ((_role = _device.fetch(:role, nil)) && _role&.has_key?(:name)) ? _role[:name] : _role&.fetch(:display, nil),
                          :cluster => ((_cluster = _device.fetch(:cluster, nil)) && _cluster&.has_key?(:name)) ? _cluster[:name] : _cluster&.fetch(:display, nil),
                          :device_type => ((_dtype = _device.fetch(:device_type, nil)) && _dtype&.has_key?(:name)) ? _dtype[:name] : _dtype&.fetch(:display, nil),
                          :manufacturer => ((_manuf = _device.dig(:device_type, :manufacturer)) && _manuf&.has_key?(:name)) ? _manuf[:name] : _manuf&.fetch(:display, nil),
                          :details => @verbose ? _device : nil }
          end
        end
        _query[:offset] += _tmp_ip_addresses.length()
        break unless (_tmp_ip_addresses.length() >= @page_size)
      else
        # weird/bad response, bail
        break
      end
    end # while true
  rescue Faraday::Error => e
    # give up aka do nothing
    puts "lookup_devices (#{ip_str}, #{site_id}): #{e.message}" if @debug
  end
  _devices
end

def autopopulate_devices(
  ip_str,
  site_id,
  autopopulate_mac,
  autopopulate_oui,
  autopopulate_default_role_name,
  autopopulate_default_dtype,
  autopopulate_default_manuf,
  autopopulate_hostname,
  autopopulate_default_status,
  nb
)

  _autopopulate_device = nil
  _autopopulate_role = nil
  _autopopulate_oui = autopopulate_oui
  _autopopulate_tags = [ @device_tag_autopopulated ]
  _autopopulate_tags << @device_tag_hostname_unknown if autopopulate_hostname.to_s.empty?

  # if MAC is set but OUI is not, do a quick lookup
  if (!autopopulate_mac.nil? && !autopopulate_mac.empty?) &&
     (_autopopulate_oui.nil? || _autopopulate_oui.empty?)
  then
    _autopopulate_oui = mac_to_oui_lookup(autopopulate_mac)
  end

  # make sure the role, manufacturer and device type exist
  _autopopulate_role = lookup_or_create_role(autopopulate_default_role_name, nb)
  _autopopulate_dtype,
  _autopopulate_manuf = lookup_or_create_manuf_and_dtype(_autopopulate_oui,
                                                         autopopulate_default_manuf,
                                                         autopopulate_default_dtype,
                                                         nb)

  # we should have found or created the autopopulate role
  begin
    if _autopopulate_role&.fetch(:id, nil)&.nonzero?

      if _autopopulate_manuf&.fetch(:vm, false)
        # a virtual machine
        _device_name = shorten_string(autopopulate_hostname.to_s.empty? ? "#{_autopopulate_manuf[:name]} @ #{ip_str}" : autopopulate_hostname)
        _device_data = { :name => _device_name,
                         :site => site_id,
                         :tags => _autopopulate_tags,
                         :status => autopopulate_default_status }
        if (_device_create_response = nb.post('virtualization/virtual-machines/', _device_data.to_json, @nb_headers).body) &&
           _device_create_response.is_a?(Hash) &&
           _device_create_response.has_key?(:id)
        then
           _autopopulate_device = _device_create_response
           _autopopulate_device[:discovered] = true
        elsif @debug
          puts('autopopulate_devices (VM: %{name}, site: %{site}): _device_create_response: %{result}' % { name: _device_name, site: site_id, result: JSON.generate(_device_create_response) })
        end

      else
        # a regular non-vm device: at this point we *must* have the manufacturer ID and device type ID
        if _autopopulate_manuf&.fetch(:id, nil)&.nonzero? &&
           _autopopulate_dtype&.fetch(:id, nil)&.nonzero?
        then

          # never figured out the manufacturer (actually, we were never even given the fields to do so), so tag it as such
          if ((_autopopulate_manuf.fetch(:name, autopopulate_default_manuf) == autopopulate_default_manuf) &&
              autopopulate_mac.to_s.empty? && _autopopulate_oui.to_s.empty?)
          then
            _autopopulate_tags << @device_tag_manufacturer_unknown
          end

          # create the device
          _device_name = shorten_string(autopopulate_hostname.to_s.empty? ? "#{_autopopulate_manuf[:name]} @ #{ip_str}" : autopopulate_hostname)
          _device_data = { :name => _device_name,
                           :device_type => _autopopulate_dtype[:id],
                           :role => _autopopulate_role[:id],
                           :site => site_id,
                           :tags => _autopopulate_tags,
                           :status => autopopulate_default_status }
          if (_device_create_response = nb.post('dcim/devices/', _device_data.to_json, @nb_headers).body) &&
             _device_create_response.is_a?(Hash) &&
             _device_create_response.has_key?(:id)
          then
             _autopopulate_device = _device_create_response
             _autopopulate_device[:discovered] = true
          elsif @debug
            puts('autopopulate_devices (device: %{name}, site: %{site}): _device_create_response: %{result}' % { name: _device_name, site: site_id, result: JSON.generate(_device_create_response) })
          end

        else
          # didn't figure out the manufacturer ID and/or device type ID, make sure we're not setting something half-populated
          _autopopulate_manuf = nil
          _autopopulate_dtype = nil
        end # _autopopulate_manuf[:id] is valid and _autopopulate_dtype[:id] is valid

      end # virtual machine vs. regular device

    else
      # didn't figure out role ID, make sure we're not setting something half-populated
      _autopopulate_role = nil
    end # site and role are valid

  rescue Faraday::Error => e
    # give up aka do nothing
    puts "autopopulate_devices (#{ip_str}, #{site_id}): #{e.message}" if @debug
  end

  return _autopopulate_device,
         _autopopulate_role,
         _autopopulate_dtype,
         _autopopulate_oui,
         _autopopulate_manuf
end

def autopopulate_prefixes(
  ip_obj,
  site_id,
  autopopulate_default_status,
  nb
)
  _autopopulate_tags = [ @device_tag_autopopulated ]

  _prefix_data = nil
  if (_private_ip_subnet = $private_ip_subnets.keys().find { |subnet| subnet.include?(ip_obj) })
    _new_prefix_ip = ip_obj.mask([_private_ip_subnet.prefix + 8, ip_obj.ipv6? ? 64 : 24].min)
    _new_prefix_name = _new_prefix_ip.to_s
    if !_new_prefix_name.to_s.include?('/')
      _new_prefix_name += '/' + _new_prefix_ip.prefix().to_s
    end
    _prefix_post = { :prefix => _new_prefix_name,
                     :description => _new_prefix_name,
                     :tags => _autopopulate_tags,
                     :scope_type => "dcim.site",
                     :scope_id => site_id,
                     :status => autopopulate_default_status }
    begin
      _new_prefix_create_response = nb.post('ipam/prefixes/', _prefix_post.to_json, @nb_headers).body
      if _new_prefix_create_response &&
         _new_prefix_create_response.is_a?(Hash) &&
         _new_prefix_create_response.has_key?(:id)
      then
          _prefix_data = { :name => _new_prefix_name,
                           :id => _new_prefix_create_response.fetch(:id, nil),
                           :site => (((_new_prefix_create_response.fetch(:scope_type, nil) == "dcim.site") && (_scope = _new_prefix_create_response.fetch(:scope, nil))) && _scope&.has_key?(:name)) ? _scope[:name] : _scope&.fetch(:display, nil),
                           :tenant => ((_tenant = _new_prefix_create_response.fetch(:tenant, nil)) && _tenant&.has_key?(:name)) ? _tenant[:name] : _tenant&.fetch(:display, nil),
                           :url => _new_prefix_create_response.fetch(:url, nil),
                           :tags => _new_prefix_create_response.fetch(:tags, nil),
                           :details => @verbose ? _new_prefix_create_response : nil }
      elsif @debug
        puts('autopopulate_prefixes (%{ip}, %{site}): _new_prefix_create_response: %{result}' % {
          ip: ip_obj.to_s,
          site: site_id,
          result: JSON.generate(_new_prefix_create_response)
        })
      end
    rescue Faraday::Error => e
      # give up aka do nothing
      puts "autopopulate_prefixes (#{ip_obj.to_s}, #{site_id}): #{e.message}" if @debug
    end
  end
  _prefix_data
end

def create_device_interface(
  ip_str,
  autopopulate_device,
  autopopulate_manuf,
  autopopulate_mac,
  nb
)

  _autopopulate_device = autopopulate_device
  _autopopulate_interface = nil
  _autopopulate_ip = nil
  _ip_obj = IPAddr.new(ip_str) rescue nil

  _interface_data = { autopopulate_manuf[:vm] ? :virtual_machine : :device => _autopopulate_device[:id],
                      :name => "e0",
                      :type => "other" }
  if !autopopulate_mac.nil? && !autopopulate_mac.empty?
    _interface_data[:mac_address] = autopopulate_mac.is_a?(Array) ? autopopulate_mac.first : autopopulate_mac
  end
  if (_interface_create_reponse = nb.post(autopopulate_manuf[:vm] ? 'virtualization/interfaces/' : 'dcim/interfaces/', _interface_data.to_json, @nb_headers).body) &&
     _interface_create_reponse.is_a?(Hash) &&
     _interface_create_reponse.has_key?(:id)
  then
     _autopopulate_interface = _interface_create_reponse
  elsif @debug
    puts('create_device_interface (%{name}): _interface_create_reponse: %{result}' % { name: ip_str, result: JSON.generate(_interface_create_reponse) })
  end

  if !_autopopulate_interface.nil? && _autopopulate_interface.fetch(:id, nil)&.nonzero?
    # interface has been created, we need to create an IP address for it
    _interface_address = ip_str
    if !_interface_address.to_s.include?('/')
      _interface_address += '/' + (_ip_obj.nil? ? '32' : _ip_obj.prefix().to_s)
    end
    _ip_data = { :address => _interface_address,
                 :assigned_object_type => autopopulate_manuf[:vm] ? "virtualization.vminterface" : "dcim.interface",
                 :assigned_object_id => _autopopulate_interface[:id],
                 :status => "active" }
    if (_ip_create_reponse = nb.post('ipam/ip-addresses/', _ip_data.to_json, @nb_headers).body) &&
       _ip_create_reponse.is_a?(Hash) &&
       _ip_create_reponse.has_key?(:id)
    then
       _autopopulate_ip = _ip_create_reponse
    elsif @debug
      puts('create_device_interface (%{name}): _ip_create_reponse: %{result}' % { name: _interface_address, result: JSON.generate(_ip_create_reponse) })
    end
  end # check if interface was created and has ID

  if !_autopopulate_ip.nil? && _autopopulate_ip.fetch(:id, nil)&.nonzero?
    # IP address was created, need to associate it as the primary IP for the device
    _primary_ip_data = { _ip_obj&.ipv6? ? :primary_ip6 : :primary_ip4 => _autopopulate_ip[:id] }
    if (_ip_primary_reponse = nb.patch("#{autopopulate_manuf[:vm] ? 'virtualization/virtual-machines' : 'dcim/devices'}/#{_autopopulate_device[:id]}/", _primary_ip_data.to_json, @nb_headers).body) &&
       _ip_primary_reponse.is_a?(Hash) &&
       _ip_primary_reponse.has_key?(:id)
    then
       _autopopulate_device = _ip_primary_reponse
    elsif @debug
      puts('create_device_interface (%{name}): _ip_primary_reponse: %{result}' % { name: _interface_address, result: JSON.generate(_ip_primary_reponse) })
    end
  end # check if the IP address was created and has an ID

  _autopopulate_device
end

def netbox_lookup(
  event:,
  ip_key:,
  site_id:,
  previous_result: nil
)
  _lookup_result = nil
  _nb = nil

  _key_ip = IPAddr.new(ip_key) rescue nil
  if assignable_private_ip?(_key_ip) && (@autopopulate || (!@target.nil? && !@target.empty?))

    _nb = NetBoxConnLazy.new(@netbox_url, @netbox_token, @debug_verbose)

    _site_obj = lookup_or_create_site(site_id, '', _nb)
    _lookup_service_port = (@lookup_service ? event.get("#{@lookup_service_port_source}") : nil).to_i
    _autopopulate_default_manuf = (@default_manuf.nil? || @default_manuf.empty?) ? "Unspecified" : @default_manuf
    _autopopulate_default_role = (@default_role.nil? || @default_role.empty?) ? "Unspecified" : @default_role
    _autopopulate_default_dtype = (@default_dtype.nil? || @default_dtype.empty?) ? "Unspecified" : @default_dtype
    _autopopulate_hostname = event.get("#{@source_hostname}")
    _autopopulate_hostname = nil if _autopopulate_hostname.to_s.end_with?('.in-addr.arpa')
    _autopopulate_mac = event.get("#{@source_mac}")
    _autopopulate_oui = event.get("#{@source_oui}")

    _autopopulate_device = nil
    _autopopulate_role = nil
    _autopopulate_dtype = nil
    _autopopulate_manuf = nil
    _prefixes = nil
    _devices = nil

    # handle :ip_device first, because if we're doing autopopulate we're also going to use
    # some of the logic from :ip_prefix

    if (@lookup_type == :ip_device)

      if (previous_result.nil? || previous_result.empty?)
        #################################################################################
        # retrieve the list of IP addresses where address matches the search key, limited to "assigned" addresses.
        # then, for those IP addresses, search for devices pertaining to the interfaces assigned to each
        # IP address (e.g., ipam.ip_address -> dcim.interface -> dcim.device, or
        # ipam.ip_address -> virtualization.interface -> virtualization.virtual_machine)
        _devices = lookup_devices(ip_key, site_id, _lookup_service_port, @netbox_url_base, @netbox_uri_suffix, _nb)

        if @autopopulate && (_devices.nil? || _devices.empty?)
          # no results found, autopopulate enabled, private-space IP address...
          # let's create an entry for this device
          _autopopulate_device,
          _autopopulate_role,
          _autopopulate_dtype,
          _autopopulate_oui,
          _autopopulate_manuf = autopopulate_devices(ip_key,
                                                     site_id,
                                                     _autopopulate_mac,
                                                     _autopopulate_oui,
                                                     _autopopulate_default_role,
                                                     _autopopulate_default_dtype,
                                                     _autopopulate_default_manuf,
                                                     _autopopulate_hostname,
                                                     @default_status,
                                                     _nb)
          if !_autopopulate_device.nil?
            # puts('5. %{key}: %{found}' % { key: autopopulate_oui, found: JSON.generate(_autopopulate_manuf) })
            # we created a device, so send it back out as the result for the event as well
            _devices = Array.new unless _devices.is_a?(Array)
            _devices << { :name => _autopopulate_device&.fetch(:name, _autopopulate_device&.fetch(:display, nil)),
                          :id => _autopopulate_device&.fetch(:id, nil),
                          :discovered => _autopopulate_device&.fetch(:discovered, nil),
                          :url => _autopopulate_device&.fetch(:url, nil),
                          :tags => _autopopulate_device&.fetch(:tags, nil),
                          :site => _site_obj&.fetch(:name, _site_obj&.fetch(:display, nil)),
                          :role => _autopopulate_role&.fetch(:name, nil),
                          :device_type => _autopopulate_dtype&.fetch(:name, nil),
                          :manufacturer => _autopopulate_manuf&.fetch(:name, nil),
                          :details => @verbose ? _autopopulate_device : nil }
          end # _autopopulate_device was not nil (i.e., we autocreated a device)
        end # _autopopulate turned on and no results found

      elsif @autopopulate

        #################################################################################
        # update with new information on an existing device (i.e., from a previous call to netbox_lookup)
        _patched_device_data = Hash.new

        # get existing tags to update them to remove "unkown-..." values if needed
        _tags = previous_result.fetch(:tags, nil)&.flatten&.map{ |hash| { slug: hash[:slug] } }&.uniq

        # API endpoints are different for VM vs real device
        _was_vm = (previous_result.fetch(:device_type, nil)&.flatten&.any? {|dt| dt == @virtual_machine_device_type_name} ||
                   (previous_result.has_key?(:url) && !previous_result[:url]&.empty? && previous_result[:url].any? { |u| u.include? "virtual-machines" }))

        # get previous device ID (should only be dealing with a single device)
        _previous_device_id = previous_result.fetch(:id, nil)&.flatten&.uniq

        # puts('netbox_lookup maybe patching %{name} (%{id}, VM old: %{oldvm}) for "%{tags}" ("%{host}", "%{mac}", "%{oui}")' % {
        #       name: ip_key,
        #       id: _previous_device_id,
        #       oldvm: _was_vm,
        #       tags: _tags.is_a?(Array) ? _tags.map{ |hash| hash[:slug] }.join('|') : '',
        #       host: _autopopulate_hostname.to_s,
        #       mac: _autopopulate_mac.to_s,
        #       oui: _autopopulate_oui.to_s }) if @debug

        if _previous_device_id.is_a?(Array) &&
          (_previous_device_id.length() == 1) &&
          (_previous_device_id = _previous_device_id.first)
        then
          if !_autopopulate_hostname.to_s.empty? &&
             _tags&.any? {|tag| tag[:slug] == @device_tag_hostname_unknown[:slug]}
          then
            # a hostname field was specified where before we had none, which means we're going to overwrite
            #   the device name previously created which was probably something like "Dell @ 192.168.10.100"
            #   and also remove the "unknown hostname" tag
            _patched_device_data[:name] = _autopopulate_hostname
            _tags = _tags.filter{|tag| tag[:slug] != @device_tag_hostname_unknown[:slug]}
          end

          if ((!_autopopulate_mac.to_s.empty? || !_autopopulate_oui.to_s.empty?) &&
              _tags&.any? {|tag| tag[:slug] == @device_tag_manufacturer_unknown[:slug]})
            # if MAC is set but OUI is not, do a quick lookup
            if (!_autopopulate_mac.nil? && !_autopopulate_mac.empty?) &&
               (_autopopulate_oui.nil? || _autopopulate_oui.empty?)
            then
              _autopopulate_oui = mac_to_oui_lookup(_autopopulate_mac)
            end
            # a MAC address or OUI field was specified where before we had none, which means we're going to overwrite
            #   the device manufacturer previously created which was probably something like "Unspecified"
            #   and also remove the "unknown manufacturer" tag
            _autopopulate_dtype,
            _autopopulate_manuf = lookup_or_create_manuf_and_dtype(_autopopulate_oui,
                                                                   _autopopulate_default_manuf,
                                                                   _autopopulate_default_dtype,
                                                                   _nb)
            if _autopopulate_dtype&.fetch(:id, nil)&.nonzero?
              _patched_device_data[:device_type] = _autopopulate_dtype[:id]
            end
            _tags = _tags.filter{|tag| tag[:slug] != @device_tag_manufacturer_unknown[:slug]}
          end

          # We could have created a device (without mac/OUI) based on hostname, and now only realize that
          #   it's actually a VM. However, a device can't have been autopopulated as a VM and then later
          #   "become" a device, since the only reason we'd have created it as a VM would be because
          #   we saw the OUI (from real traffic) in @vm_namesarray in the first place.
          _is_vm = _was_vm || (_autopopulate_manuf.is_a?(Hash) && (_autopopulate_manuf.fetch(:vm, false) == true))
          _device_to_vm = ((_was_vm == false) && (_is_vm == true))

          if !_patched_device_data.empty? || _device_to_vm
            # we've got changes to make, so do it
            _device_written = false

            puts('netbox_lookup patching %{name} @ %{site} (%{id}, VM: %{wasvm}->%{isvm}) ("%{host}", "%{mac}", "%{oui}"): %{changes}' % {
                  name: ip_key,
                  site: site_id,
                  id: _previous_device_id,
                  wasvm: _was_vm,
                  isvm: _is_vm,
                  host: _autopopulate_hostname.to_s,
                  mac: _autopopulate_mac.to_s,
                  oui: _autopopulate_oui.to_s,
                  changes: JSON.generate(_patched_device_data) }) if @debug

            if _device_to_vm
              # you can't "convert" a device to a VM, so we have to create a new VM then delete the old device
              _vm_data = { :name => _patched_device_data.fetch(:name, [previous_result.fetch(:name, nil)])&.flatten&.uniq.first,
                           :site => site_id,
                           :tags => _tags,
                           :status => @default_status }
              if (_vm_create_response = _nb.post('virtualization/virtual-machines/', _vm_data.to_json, @nb_headers).body) &&
                 _vm_create_response.is_a?(Hash) &&
                 _vm_create_response.has_key?(:id)
              then
                _device_written = true
                _autopopulate_device = _vm_create_response
                # we've created the device as a VM, create_device_interface will be called below to create its interface

                # now delete the old device entry
                _old_device_delete_response = _nb.delete("dcim/devices/#{_previous_device_id}/")
                puts('netbox_lookup (%{name}: dev.%{oldid} -> vm.%{newid}) deletion failed' % {
                     name: _vm_data[:name],
                     oldid: _previous_device_id,
                     newid: _vm_create_response[:id] }) if (@debug && !_old_device_delete_response.success?)
              elsif @debug
                puts('netbox_lookup (%{name}): _vm_create_response: %{result}' % { name: _vm_data[:name], result: JSON.generate(_vm_create_response) })
              end

            elsif (_is_vm == _was_vm)
              # the type of object (vm vs. device) is the same as it was before, so we're just doing an update
              _patched_device_data[:tags] = _tags
              if (_patched_device_response = _nb.patch("#{_was_vm ? 'virtualization/virtual-machines' : 'dcim/devices'}/#{_previous_device_id}/", _patched_device_data.to_json, @nb_headers).body) &&
                 _patched_device_response.is_a?(Hash) &&
                 _patched_device_response.has_key?(:id)
              then
                _device_written = true
              elsif @debug
                puts('netbox_lookup (%{prev_id}): _patched_device_response: %{result}' % { prev_id: _previous_device_id, result: JSON.generate(_patched_device_response) })
              end # _nb.patch succeeded
            end # _is_vm vs _was_vm check

            # we've made the change to netbox, do a call to lookup_devices to get the formatted/updated data
            #   (yeah, this is a *little* inefficient, but this should really only happen one extra time per device at most)
            _devices = lookup_devices(ip_key, site_id, _lookup_service_port, @netbox_url_base, @netbox_uri_suffix, _nb) if _device_written

          end # check _patched_device_data, _device_to_vm

        end # check previous device ID is valid
      end # check on previous_result function argument

      if !_devices.nil?
        _devices = collect_values(crush(_devices))
        _devices.fetch(:service, [])&.flatten!&.uniq!
        _lookup_result = _devices
      end
    end # @lookup_type == :ip_device

    # this || is because we are going to need to do the prefix lookup if we're autopopulating
    # as well as if we're specifically requested to do that enrichment

    if (@lookup_type == :ip_prefix) || !_autopopulate_device.nil?
    #################################################################################
      # retrieve the list of IP address prefixes containing the search key
      _prefixes = lookup_prefixes(ip_key, site_id, _nb)

      if (_prefixes.nil? || _prefixes.empty?) && @autopopulate_create_prefix
        # we didn't find a prefix containing this private-space IPv4 address and auto-create is true
        _prefix_info = autopopulate_prefixes(_key_ip, site_id, @default_status, _nb)
        _prefixes = Array.new unless _prefixes.is_a?(Array)
        _prefixes << _prefix_info
      end # if auto-create prefix

      _prefixes = collect_values(crush(_prefixes))
      _lookup_result = _prefixes unless (@lookup_type != :ip_prefix)
    end # @lookup_type == :ip_prefix

    if !_autopopulate_device.nil? && _autopopulate_device.fetch(:id, nil)&.nonzero?
      # device has been created, we need to create an interface for it
      _autopopulate_device = create_device_interface(ip_key,
                                                     _autopopulate_device,
                                                     _autopopulate_manuf,
                                                     _autopopulate_mac,
                                                     _nb)
    end # check if device was created and has ID
  end # IP address is private IP

  # yield return value for _lookup_hash getset
  return (!_lookup_result.nil? && !_lookup_result.empty?) ? _lookup_result : nil, _key_ip, _nb&.initialized? || false
end

###############################################################################
# tests

###############################################################################