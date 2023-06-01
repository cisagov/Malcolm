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
  #   valid values are: ip_device, ip_vrf
  @lookup_type = params.fetch("lookup_type", "").to_sym

  # site value to include in queries for enrichment lookups, either specified directly or read from ENV
  @lookup_site = params["lookup_site"]
  _lookup_site_env = params["lookup_site_env"]
  if @lookup_site.nil? and !_lookup_site_env.nil?
    @lookup_site = ENV[_lookup_site_env]
  end
  if !@lookup_site.nil? && @lookup_site.empty? then
    @lookup_site = nil
  end

  # whether or not to enrich service for ip_device
  _lookup_service_str = params["lookup_service"]
  _lookup_service_env = params["lookup_service_env"]
  if _lookup_service_str.nil? and !_lookup_service_env.nil?
    _lookup_service_str = ENV[_lookup_service_env]
  end
  @lookup_service = [1, true, '1', 'true', 't', 'on', 'enabled'].include?(_lookup_service_str.to_s.downcase)
  @lookup_service_port_source = params.fetch("lookup_service_port_source", "[destination][port]")

  # API parameters
  @page_size = params.fetch("page_size", 50)

  # caching parameters
  @cache_size = params.fetch("cache_size", 1000)
  @cache_ttl = params.fetch("cache_ttl", 600)

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

  # autopopulate - either specified directly or read from ENV via autopopulate_env
  #   false - do not autopopulate netbox inventory when uninventoried devices are observed
  #   true - autopopulate netbox inventory when uninventoried devices are observed (not recommended)
  #
  # For now this is only done for devices/virtual machines, not for services or network segments.
  _autopopulate_str = params["autopopulate"]
  _autopopulate_env = params["autopopulate_env"]
  if _autopopulate_str.nil? and !_autopopulate_env.nil?
    _autopopulate_str = ENV[_autopopulate_env]
  end
  @autopopulate = [1, true, '1', 'true', 't', 'on', 'enabled'].include?(_autopopulate_str.to_s.downcase)

  # connection URL for netbox
  @netbox_url = params.fetch("netbox_url", "http://netbox:8080/netbox/api").delete_suffix("/")
  @netbox_url_suffix = "/netbox/api"
  @netbox_url_base = @netbox_url.delete_suffix(@netbox_url_suffix)

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
  _url_base = @netbox_url_base
  _url_suffix = @netbox_url_suffix
  _token = @netbox_token
  _page_size = @page_size
  _verbose = @verbose
  _lookup_type = @lookup_type
  _lookup_site = @lookup_site
  _lookup_service_port = (@lookup_service ? event.get("#{@lookup_service_port_source}") : nil).to_i
  _result = @cache_hash.getset(_lookup_type){
              LruRedux::TTL::ThreadSafeCache.new(@cache_size, @cache_ttl)
            }.getset(_key){

              _nb = Faraday.new(_url) do |conn|
                conn.request :authorization, 'Token', _token
                conn.request :url_encoded
                conn.response :json, :parser_options => { :symbolize_names => true }
              end

              case _lookup_type
              #################################################################################
              when :ip_vrf
                # retrieve the list VRFs containing IP address prefixes containing the search key
                _vrfs = Array.new
                _query = {:contains => _key, :offset => 0, :limit => _page_size}
                _query[:site_n] = _lookup_site unless _lookup_site.nil? || _lookup_site&.empty?
                begin
                  while true do
                    if (_prefixes_response = _nb.get('ipam/prefixes/', _query).body) and _prefixes_response.is_a?(Hash) then
                      _tmp_prefixes = _prefixes_response.fetch(:results, [])
                      _tmp_prefixes.each do |p|
                        if (_vrf = p.fetch(:vrf, nil))
                          # non-verbose output is flatter with just names { :name => "name", :id => "id", ... }
                          # if _verbose, include entire object as :details
                          _vrfs << { :name => _vrf.fetch(:name, _vrf.fetch(:display, nil)),
                                     :id => _vrf.fetch(:id, nil),
                                     :site => ((_site = p.fetch(:site, nil)) && _site&.key?(:name)) ? _site[:name] : _site&.fetch(:display, nil),
                                     :tenant => ((_tenant = p.fetch(:tenant, nil)) && _tenant&.key?(:name)) ? _tenant[:name] : _tenant&.fetch(:display, nil),
                                     :url => p.fetch(:url, _vrf.fetch(:url, nil)),
                                     :details => _verbose ? _vrf.merge({:prefix => p.tap { |h| h.delete(:vrf) }}) : nil }
                        end
                      end
                      _query[:offset] += _tmp_prefixes.length()
                      break unless (_tmp_prefixes.length() >= _page_size)
                    else
                      break
                    end
                  end
                rescue Faraday::Error
                  # give up aka do nothing
                end
                collect_values(crush(_vrfs))

              #################################################################################
              when :ip_device
                # retrieve the list IP addresses where address matches the search key, limited to "assigned" addresses.
                # then, for those IP addresses, search for devices pertaining to the interfaces assigned to each
                # IP address (e.g., ipam.ip_address -> dcim.interface -> dcim.device, or
                # ipam.ip_address -> virtualization.interface -> virtualization.virtual_machine)
                _devices = Array.new
                _query = {:address => _key, :offset => 0, :limit => _page_size}
                begin
                  while true do
                    if (_ip_addresses_response = _nb.get('ipam/ip-addresses/', _query).body) and _ip_addresses_response.is_a?(Hash) then
                      _tmp_ip_addresses = _ip_addresses_response.fetch(:results, [])
                      _tmp_ip_addresses.each do |i|
                        _is_device = nil
                        if (_obj = i.fetch(:assigned_object, nil)) && ((_device_obj = _obj.fetch(:device, nil)) || (_virtualized_obj = _obj.fetch(:virtual_machine, nil)))
                          _is_device = !_device_obj.nil?
                          _device = _is_device ? _device_obj : _virtualized_obj
                          # if we can, follow the :assigned_object's "full" device URL to get more information
                          _device = (_device.key?(:url) and (_full_device = _nb.get(_device[:url].delete_prefix(_url_base).delete_prefix(_url_suffix).delete_prefix("/")).body)) ? _full_device : _device
                          _device_id = _device.fetch(:id, nil)
                          _device_site = ((_site = _device.fetch(:site, nil)) && _site&.key?(:name)) ? _site[:name] : _site&.fetch(:display, nil)
                          next unless (_device_site.to_s.downcase == _lookup_site.to_s.downcase) || _lookup_site.nil? || _lookup_site&.empty? || _device_site.nil? || _device_site&.empty?
                          # look up service if requested (based on device/vm found and service port)
                          if (_lookup_service_port > 0) then
                            _services = Array.new
                            _service_query = { (_is_device ? :device_id : :virtual_machine_id) => _device_id, :port => _lookup_service_port, :offset => 0, :limit => _page_size }
                            while true do
                              if (_services_response = _nb.get('ipam/services/', _service_query).body) and _services_response.is_a?(Hash) then
                                _tmp_services = _services_response.fetch(:results, [])
                                _services.unshift(*_tmp_services) unless _tmp_services.nil? || _tmp_services&.empty?
                                _service_query[:offset] += _tmp_services.length()
                                break unless (_tmp_services.length() >= _page_size)
                              else
                                break
                              end
                            end
                            _device[:service] = _services
                          end
                          # non-verbose output is flatter with just names { :name => "name", :id => "id", ... }
                          # if _verbose, include entire object as :details
                          _devices << { :name => _device.fetch(:name, _device.fetch(:display, nil)),
                                        :id => _device_id,
                                        :url => _device.fetch(:url, nil),
                                        :service => _device.fetch(:service, []).map {|s| s.fetch(:name, s.fetch(:display, nil)) },
                                        :site => _device_site,
                                        :role => ((_role = _device.fetch(:role, _device.fetch(:device_role, nil))) && _role&.key?(:name)) ? _role[:name] : _role&.fetch(:display, nil),
                                        :cluster => ((_cluster = _device.fetch(:cluster, nil)) && _cluster&.key?(:name)) ? _cluster[:name] : _cluster&.fetch(:display, nil),
                                        :device_type => ((_dtype = _device.fetch(:device_type, nil)) && _dtype&.key?(:name)) ? _dtype[:name] : _dtype&.fetch(:display, nil),
                                        :manufacturer => ((_manuf = _device.dig(:device_type, :manufacturer)) && _manuf&.key?(:name)) ? _manuf[:name] : _manuf&.fetch(:display, nil),
                                        :details => _verbose ? _device : nil }
                        end
                      end
                      _query[:offset] += _tmp_ip_addresses.length()
                      break unless (_tmp_ip_addresses.length() >= _page_size)
                    else
                      break
                    end
                  end
                rescue Faraday::Error
                  # give up aka do nothing
                end
                _devices = collect_values(crush(_devices))
                _devices.fetch(:service, [])&.flatten!&.uniq!
                _devices

              #################################################################################
              else
                nil
              end
            }

  if !_result.nil? && _result.key?(:url) && !_result[:url]&.empty? then
    _result[:url].map! { |u| u.delete_prefix(@netbox_url_base).gsub('/api/', '/') }
    if (_lookup_type == :ip_device) && (!_result.key?(:device_type) || _result[:device_type]&.empty?) && _result[:url].any? { |u| u.include? "virtual-machines" } then
      _result[:device_type] = [ "Virtual Machine" ]
    end
  end
  event.set("#{@target}", _result) unless _result.nil? || _result&.empty?

  [event]
end

def collect_values(hashes)
  # https://stackoverflow.com/q/5490952
  hashes.reduce({}){ |h, pairs| pairs.each { |k,v| (h[k] ||= []) << v}; h }
end

def crush(thing)
  if thing.is_a?(Array)
    thing.each_with_object([]) do |v, a|
      v = crush(v)
      a << v unless [nil, [], {}, "", "Unspecified", "unspecified"].include?(v)
    end
  elsif thing.is_a?(Hash)
    thing.each_with_object({}) do |(k,v), h|
      v = crush(v)
      h[k] = v unless [nil, [], {}, "", "Unspecified", "unspecified"].include?(v)
    end
  else
    thing
  end
end

###############################################################################
# tests

###############################################################################