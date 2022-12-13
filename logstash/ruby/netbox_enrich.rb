def concurrency
  :shared
end

def register(params)
  require 'date'
  require 'faraday'
  require 'json'
  require 'lru_redux'

  # global enable/disable for this plugin based on environment variable(s)
  @netbox_enabled = (not [1, true, '1', 'true', 't', 'on', 'enabled'].include?(ENV["NETBOX_DISABLED"].to_s.downcase)) &&
                    [1, true, '1', 'true', 't', 'on', 'enabled'].include?(ENV["LOGSTASH_NETBOX_ENRICHMENT"].to_s.downcase)

  # source field containing lookup value
  @source = params["source"]

  # lookup type
  #   valid values are: ip_device, ip_vrf, mac_device
  @lookup_type = params.fetch("lookup_type", "").to_sym

  # API parameters
  @page_size = params.fetch("page_size", 50)

  # caching parameters
  @cache_size = params.fetch("cache_size", 500)
  @cache_ttl = params.fetch("cache_ttl", 300)

  # target field to store looked-up value
  @target = params["target"]

  # verbose - either specified directly or read from ENV via verbose_env
  #   false - store the "name" (fallback to "display") and "id" value(s) as @target.name and @target.id
  #             e.g., (@target is destination.segment) destination.segment.name => ["foobar"]
  #                                                    destination.segment.id => [123]
  #   true - store a hash of arrays *under* @target
  #             e.g., (@target is destination.segment) destination.segment.name => ["foobar"]
  #                                                    destination.segment.id => [123]
  #                                                    destination.segment.url => ["whatever"]
  #                                                    destination.segment.foo => ["bar"]
  #                                                    etc.
  _verbose_str = params["verbose"]
  _verbose_env = params["verbose_env"]
  if _verbose_str.nil? and !_verbose_env.nil?
    _verbose_str = ENV[_verbose_env]
  end
  @verbose = [1, true, '1', 'true', 't', 'on', 'enabled'].include?(_verbose_str.to_s.downcase)

  # connection URL for netbox
  @netbox_url = params.fetch("netbox_url", "http://netbox:8080/netbox/api").chomp("/")
  @netbox_url_base = @netbox_url.delete_suffix("/netbox/api")

  # connection token (either specified directly or read from ENV via netbox_token_env)
  @netbox_token = params["netbox_token"]
  _netbox_token_env = params["netbox_token_env"]
  if @netbox_token.nil? and !_netbox_token_env.nil?
    @netbox_token = ENV[_netbox_token_env]
  end

  # hash of lookup types (from @lookup_type), each of which contains the respective looked-up values
  @cache_hash = LruRedux::ThreadSafeCache.new(params.fetch("lookup_cache_size", 512))
end

def filter(event)
  _key = event.get("#{@source}")
  if (not @netbox_enabled) || @lookup_type.nil? || @lookup_type&.empty? || _key.nil? || _key&.empty?
    return [event]
  end

  _url = @netbox_url
  _token = @netbox_token
  _page_size = @page_size
  _verbose = @verbose
  _result = @cache_hash.getset(@lookup_type){
              LruRedux::TTL::ThreadSafeCache.new(@cache_size, @cache_ttl)
            }.getset(_key){

              _nb = Faraday.new(_url) do |conn|
                conn.request :authorization, 'Token', _token
                conn.request :url_encoded
                conn.response :json, :parser_options => { :symbolize_names => true }
              end

              case @lookup_type
              #################################################################################
              when :ip_vrf
                # retrieve the list VRFs containing IP address prefixes containing the search key
                _vrfs = Array.new
                _query = {:contains => _key, :offset => 0, :limit => _page_size}
                while true do
                    _tmp_prefixes = _nb.get('ipam/prefixes/', _query).body.fetch(:results, [])
                    _tmp_prefixes.each do |p|
                        if (_vrf = p.fetch(:vrf, nil))
                          if _verbose then
                            _vrfs << _vrf
                          else
                            _vrfs << {:name => _vrf.fetch(:name, _vrf.fetch(:display, nil)),
                                      :id => _vrf.fetch(:id, nil)}
                          end
                        end
                    end
                    _query[:offset] += _tmp_prefixes.length()
                    break unless (_tmp_prefixes.length() >= _page_size)
                end
                collect_values(_vrfs)

              #################################################################################
              when :ip_device
                # retrieve the list IP addresses where address matches the search key, limited to "assigned" addresses.
                # then, for those IP addresses, search for devices pertaining to the interfaces assigned to each
                # IP address (e.g., ipam.ip_address -> dcim.interface -> dcim.device, or
                # ipam.ip_address -> virtualization.interface -> virtualization.virtual_machine)
                _devices = Array.new
                _query = {:address => _key, :offset => 0, :limit => _page_size}
                while true do
                    _tmp_ip_addresses = _nb.get('ipam/ip-addresses/', _query).body.fetch(:results, [])
                    _tmp_ip_addresses.each do |i|
                        if (_obj = i.fetch(:assigned_object, nil)) && ((_device = _obj.fetch(:device, nil)) || (_device = _obj.fetch(:virtual_machine, nil)))
                          if _verbose then
                            _devices << _device
                          else
                            _devices << {:name => _device.fetch(:name, _device.fetch(:display, nil)),
                                         :id => _device.fetch(:id, nil)}
                          end
                        end
                    end
                    _query[:offset] += _tmp_ip_addresses.length()
                    break unless (_tmp_ip_addresses.length() >= _page_size)
                end
                collect_values(_devices)

              #################################################################################
              else
                nil
              end
            }

  if !_result.nil? && _result.key?(:url) && !_result[:url]&.empty? then
    _result[:url].map! { |u| u.delete_prefix(@netbox_url_base) }
  end
  event.set("#{@target}", _result) unless _result.nil? || _result&.empty?

  [event]
end

def collect_values(hashes)
  {}.tap{ |r| hashes.compact.uniq.each{ |h| h.compact.each{ |k,v| (r[k]||=[]) << v } } }
end

###############################################################################
# tests

###############################################################################