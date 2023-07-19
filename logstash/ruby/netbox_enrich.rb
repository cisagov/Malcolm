def concurrency
  :shared
end

def register(params)
  require 'date'
  require 'faraday'
  require 'fuzzystringmatch'
  require 'ipaddr'
  require 'json'
  require 'lru_redux'
  require 'stringex_lite'

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
  if _verbose_str.nil? && !_verbose_env.nil?
    _verbose_str = ENV[_verbose_env]
  end
  @verbose = [1, true, '1', 'true', 't', 'on', 'enabled'].include?(_verbose_str.to_s.downcase)

  # connection URL for netbox
  @netbox_url = params.fetch("netbox_url", "http://netbox:8080/netbox/api").delete_suffix("/")
  @netbox_url_suffix = "/netbox/api"
  @netbox_url_base = @netbox_url.delete_suffix(@netbox_url_suffix)

  # connection token (either specified directly or read from ENV via netbox_token_env)
  @netbox_token = params["netbox_token"]
  _netbox_token_env = params["netbox_token_env"]
  if @netbox_token.nil? && !_netbox_token_env.nil?
    @netbox_token = ENV[_netbox_token_env]
  end

  # hash of lookup types (from @lookup_type), each of which contains the respective looked-up values
  @cache_hash = LruRedux::ThreadSafeCache.new(params.fetch("lookup_cache_size", 512))

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

  # default manufacturer, device role and device type if not specified, either specified directly or read from ENVs
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
    YAML.safe_load(File.read(_vendor_oui_map_path)).each do |mac|
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
    YAML.safe_load(File.read(_vm_oui_map_path)).each do |mac|
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

  @default_drole = params["default_drole"]
  _default_drole_env = params["default_drole_env"]
  if @default_drole.nil? && !_default_drole_env.nil?
    @default_drole = ENV[_default_drole_env]
  end
  if !@default_drole.nil? && @default_drole.empty?
    @default_drole = nil
  end

  # threshold for fuzzy string matching (for manufacturer, etc.)
  _autopopulate_fuzzy_threshold_str = params["autopopulate_fuzzy_threshold"]
  _autopopulate_fuzzy_threshold_str_env = params["autopopulate_fuzzy_threshold_env"]
  if _autopopulate_fuzzy_threshold_str.nil? && !_autopopulate_fuzzy_threshold_str_env.nil?
    _autopopulate_fuzzy_threshold_str = ENV[_autopopulate_fuzzy_threshold_str_env]
  end
  if _autopopulate_fuzzy_threshold_str.nil? || _autopopulate_fuzzy_threshold_str.empty?
    @autopopulate_fuzzy_threshold = 0.75
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

  # case-insensitive hash of OUIs (https://standards-oui.ieee.org/) to Manufacturers (https://demo.netbox.dev/static/docs/core-functionality/device-types/)
  @manuf_hash = LruRedux::ThreadSafeCache.new(params.fetch("manuf_cache_size", 2048))

  # case-insensitive hash of device role names to IDs
  @drole_hash = LruRedux::ThreadSafeCache.new(params.fetch("drole_cache_size", 128))

  # case-insensitive hash of site names to IDs
  @site_hash = LruRedux::ThreadSafeCache.new(params.fetch("site_cache_size", 128))

  # end of autopopulation arguments

end

def filter(event)
  _key = event.get("#{@source}")
  if (not @netbox_enabled) || @lookup_type.nil? || @lookup_type.empty? || _key.nil? || _key.empty?
    return [event]
  end

  _key_ip = IPAddr.new(_key) rescue nil
  _url = @netbox_url
  _url_base = @netbox_url_base
  _url_suffix = @netbox_url_suffix
  _token = @netbox_token
  _page_size = @page_size
  _verbose = @verbose
  _lookup_type = @lookup_type
  _lookup_site = @lookup_site
  _lookup_service_port = (@lookup_service ? event.get("#{@lookup_service_port_source}") : nil).to_i
  _autopopulate = @autopopulate
  _autopopulate_default_manuf = (@default_manuf.nil? || @default_manuf.empty?) ? "Unspecified" : @default_manuf
  _autopopulate_default_drole = (@default_drole.nil? || @default_drole.empty?) ? "Unspecified" : @default_drole
  _autopopulate_default_dtype = (@default_dtype.nil? || @default_dtype.empty?) ? "Unspecified" : @default_dtype
  _autopopulate_default_site =  (@lookup_site.nil? || @lookup_site.empty?) ? "default" : @lookup_site
  _autopopulate_fuzzy_threshold = @autopopulate_fuzzy_threshold
  _autopopulate_create_manuf = @autopopulate_create_manuf && !_autopopulate_oui.nil? && !_autopopulate_oui.empty?
  _autopopulate_hostname = event.get("#{@source_hostname}")
  _autopopulate_mac = event.get("#{@source_mac}")
  _autopopulate_oui = event.get("#{@source_oui}")

  _result = @cache_hash.getset(_lookup_type){
              LruRedux::TTL::ThreadSafeCache.new(@cache_size, @cache_ttl)
            }.getset(_key){

              _nb = Faraday.new(_url) do |conn|
                conn.request :authorization, 'Token', _token
                conn.request :url_encoded
                conn.response :json, :parser_options => { :symbolize_names => true }
              end
              _nb_headers = { 'Content-Type': 'application/json' }

              _lookup_result = nil
              _autopopulate_device = nil
              _autopopulate_drole = nil
              _autopopulate_dtype = nil
              _autopopulate_interface = nil
              _autopopulate_ip = nil
              _autopopulate_manuf = nil
              _autopopulate_site = nil
              _vrfs = nil
              _devices = nil
              _exception_error = false

              # handle :ip_device first, because if we're doing autopopulate we're also going to use
              # some of the logic from :ip_vrf

              if (_lookup_type == :ip_device)
              #################################################################################
                # retrieve the list of IP addresses where address matches the search key, limited to "assigned" addresses.
                # then, for those IP addresses, search for devices pertaining to the interfaces assigned to each
                # IP address (e.g., ipam.ip_address -> dcim.interface -> dcim.device, or
                # ipam.ip_address -> virtualization.interface -> virtualization.virtual_machine)
                _devices = Array.new
                _query = { :address => _key,
                           :offset => 0,
                           :limit => _page_size }
                begin
                  while true do
                    if (_ip_addresses_response = _nb.get('ipam/ip-addresses/', _query).body) &&
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
                          _device = (_device.has_key?(:url) && (_full_device = _nb.get(_device[:url].delete_prefix(_url_base).delete_prefix(_url_suffix).delete_prefix("/")).body)) ? _full_device : _device
                          _device_id = _device.fetch(:id, nil)
                          _device_site = ((_site = _device.fetch(:site, nil)) && _site&.has_key?(:name)) ? _site[:name] : _site&.fetch(:display, nil)
                          next unless (_device_site.to_s.downcase == _lookup_site.to_s.downcase) || _lookup_site.nil? || _lookup_site.empty? || _device_site.nil? || _device_site.empty?
                          # look up service if requested (based on device/vm found and service port)
                          if (_lookup_service_port > 0)
                            _services = Array.new
                            _service_query = { (_is_device ? :device_id : :virtual_machine_id) => _device_id, :port => _lookup_service_port, :offset => 0, :limit => _page_size }
                            while true do
                              if (_services_response = _nb.get('ipam/services/', _service_query).body) &&
                                 _services_response.is_a?(Hash)
                              then
                                _tmp_services = _services_response.fetch(:results, [])
                                _services.unshift(*_tmp_services) unless _tmp_services.nil? || _tmp_services.empty?
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
                                        :role => ((_role = _device.fetch(:role, _device.fetch(:device_role, nil))) && _role&.has_key?(:name)) ? _role[:name] : _role&.fetch(:display, nil),
                                        :cluster => ((_cluster = _device.fetch(:cluster, nil)) && _cluster&.has_key?(:name)) ? _cluster[:name] : _cluster&.fetch(:display, nil),
                                        :device_type => ((_dtype = _device.fetch(:device_type, nil)) && _dtype&.has_key?(:name)) ? _dtype[:name] : _dtype&.fetch(:display, nil),
                                        :manufacturer => ((_manuf = _device.dig(:device_type, :manufacturer)) && _manuf&.has_key?(:name)) ? _manuf[:name] : _manuf&.fetch(:display, nil),
                                        :details => _verbose ? _device : nil }
                        end
                      end
                      _query[:offset] += _tmp_ip_addresses.length()
                      break unless (_tmp_ip_addresses.length() >= _page_size)
                    else
                      # weird/bad response, bail
                      _exception_error = true
                      break
                    end
                  end # while true
                rescue Faraday::Error
                  # give up aka do nothing
                  _exception_error = true
                end

                if _autopopulate && (_query[:offset] == 0) && !_exception_error && _key_ip&.private?

                  # no results found, autopopulate enabled, private-space IP address...
                  # let's create an entry for this device

                  # if MAC is set but OUI is not, do a quick lookup
                  if (!_autopopulate_mac.nil? && !_autopopulate_mac.empty?) &&
                     (_autopopulate_oui.nil? || _autopopulate_oui.empty?)
                  then
                    case _autopopulate_mac
                    when String
                      if @macregex.match?(_autopopulate_mac)
                        _macint = mac_string_to_integer(_autopopulate_mac)
                        _vendor = @macarray.bsearch{ |_vendormac| (_macint < _vendormac[0]) ? -1 : ((_macint > _vendormac[1]) ? 1 : 0)}
                        _autopopulate_oui = _vendor[2] unless _vendor.nil?
                      end # _autopopulate_mac matches @macregex
                    when Array
                      _autopopulate_mac.each do |_addr|
                        if @macregex.match?(_addr)
                          _macint = mac_string_to_integer(_addr)
                          _vendor = @macarray.bsearch{ |_vendormac| (_macint < _vendormac[0]) ? -1 : ((_macint > _vendormac[1]) ? 1 : 0)}
                          if !_vendor.nil?
                            _autopopulate_oui = _vendor[2]
                            break
                          end # !_vendor.nil?
                        end # _addr matches @macregex
                      end # _autopopulate_mac.each do
                    end # case statement _autopopulate_mac String vs. Array
                  end # MAC is populated but OUI is not

                  # match/look up manufacturer based on OUI
                  if !_autopopulate_oui.nil? && !_autopopulate_oui.empty?

                    _autopopulate_oui = _autopopulate_oui.first() unless !_autopopulate_oui.is_a?(Array)

                    # does it look like a VM or a regular device?
                    if @vm_namesarray.include?(_autopopulate_oui.downcase)
                      # looks like this is probably a virtual machine
                      _autopopulate_manuf = { :name => _autopopulate_oui,
                                              :match => 1.0,
                                              :vm => true,
                                              :id => nil }

                    else
                      # looks like this is not a virtual machine (or we can't tell) so assume its' a regular device
                      _autopopulate_manuf = @manuf_hash.getset(_autopopulate_oui) {
                        _fuzzy_matcher = FuzzyStringMatch::JaroWinkler.create( :pure )
                        _manufs = Array.new
                        # fetch the manufacturers to do the comparison. this is a lot of work
                        # and not terribly fast but once the hash it populated it shouldn't happen too often
                        _query = { :offset => 0,
                                   :limit => _page_size }
                        begin
                          while true do
                            if (_manufs_response = _nb.get('dcim/manufacturers/', _query).body) &&
                               _manufs_response.is_a?(Hash)
                            then
                              _tmp_manufs = _manufs_response.fetch(:results, [])
                              _tmp_manufs.each do |_manuf|
                                _tmp_name = _manuf.fetch(:name, _manuf.fetch(:display, nil))
                                _manufs << { :name => _tmp_name,
                                             :id => _manuf.fetch(:id, nil),
                                             :url => _manuf.fetch(:url, nil),
                                             :match => _fuzzy_matcher.getDistance(_tmp_name.to_s.downcase, _autopopulate_oui.to_s.downcase),
                                             :vm => false
                                           }
                              end
                              _query[:offset] += _tmp_manufs.length()
                              break unless (_tmp_manufs.length() >= _page_size)
                            else
                              break
                            end
                          end
                        rescue Faraday::Error
                          # give up aka do nothing
                          _exception_error = true
                        end
                        # return the manuf with the highest match
                        !_manufs&.empty? ? _manufs.max_by{|k| k[:match] } : nil
                      }
                    end # virtual machine vs. regular device
                  end # _autopopulate_oui specified

                  if !_autopopulate_manuf.is_a?(Hash)
                    # no match was found at ANY match level (empty database or no OUI specified), set default ("unspecified") manufacturer
                    _autopopulate_manuf = { :name => _autopopulate_create_manuf ? _autopopulate_oui : _autopopulate_default_manuf,
                                            :match => 0.0,
                                            :vm => false,
                                            :id => nil}
                  end

                  # make sure the site and device role exists

                  _autopopulate_site = @site_hash.getset(_autopopulate_default_site) {
                    begin
                      _site = nil

                      # look it up first
                      _query = { :offset => 0,
                                 :limit => 1,
                                 :name => _autopopulate_default_site }
                      if (_sites_response = _nb.get('dcim/sites/', _query).body) &&
                         _sites_response.is_a?(Hash) &&
                         (_tmp_sites = _sites_response.fetch(:results, [])) &&
                         (_tmp_sites.length() > 0)
                      then
                         _site = _tmp_sites.first
                      end

                      if _site.nil?
                        # the device site is not found, create it
                        _site_data = { :name => _autopopulate_default_site,
                                       :slug => _autopopulate_default_site.to_url,
                                       :status => "active" }
                        if (_site_create_response = _nb.post('dcim/sites/', _site_data.to_json, _nb_headers).body) &&
                           _site_create_response.is_a?(Hash) &&
                           _site_create_response.has_key?(:id)
                        then
                           _site = _site_create_response
                        end
                      end

                    rescue Faraday::Error
                      # give up aka do nothing
                      _exception_error = true
                    end
                    _site
                  }

                  _autopopulate_drole = @drole_hash.getset(_autopopulate_default_drole) {
                    begin
                      _drole = nil

                      # look it up first
                      _query = { :offset => 0,
                                 :limit => 1,
                                 :name => _autopopulate_default_drole }
                      if (_droles_response = _nb.get('dcim/device-roles/', _query).body) &&
                         _droles_response.is_a?(Hash) &&
                         (_tmp_droles = _droles_response.fetch(:results, [])) &&
                         (_tmp_droles.length() > 0)
                      then
                         _drole = _tmp_droles.first
                      end

                      if _drole.nil?
                        # the device role is not found, create it
                        _drole_data = { :name => _autopopulate_default_drole,
                                        :slug => _autopopulate_default_drole.to_url,
                                        :color => "d3d3d3" }
                        if (_drole_create_response = _nb.post('dcim/device-roles/', _drole_data.to_json, _nb_headers).body) &&
                           _drole_create_response.is_a?(Hash) &&
                           _drole_create_response.has_key?(:id)
                        then
                           _drole = _drole_create_response
                        end
                      end

                    rescue Faraday::Error
                      # give up aka do nothing
                      _exception_error = true
                    end
                    _drole
                  }

                  # we should have found or created the autopopulate device role and site
                  begin
                    if _autopopulate_site&.fetch(:id, nil)&.nonzero? &&
                       _autopopulate_drole&.fetch(:id, nil)&.nonzero?
                    then

                      if _autopopulate_manuf[:vm]
                        # a virtual machine
                        _device_name = _autopopulate_hostname.to_s.empty? ? "#{_autopopulate_manuf[:name]} @ #{_key}" : "#{_autopopulate_hostname} @ #{_key}"
                        _device_data = { :name => _device_name,
                                         :site => _autopopulate_site[:id],
                                         :status => "staged" }
                        if (_device_create_response = _nb.post('virtualization/virtual-machines/', _device_data.to_json, _nb_headers).body) &&
                           _device_create_response.is_a?(Hash) &&
                           _device_create_response.has_key?(:id)
                        then
                           _autopopulate_device = _device_create_response
                        end

                      else
                        # a regular non-vm device

                        if !_autopopulate_manuf.fetch(:id, nil)&.nonzero?
                          # the manufacturer was default (not found) so look it up first
                          _query = { :offset => 0,
                                     :limit => 1,
                                     :name => _autopopulate_manuf[:name] }
                          if (_manufs_response = _nb.get('dcim/manufacturers/', _query).body) &&
                             _manufs_response.is_a?(Hash) &&
                             (_tmp_manufs = _manufs_response.fetch(:results, [])) &&
                             (_tmp_manufs.length() > 0)
                          then
                             _autopopulate_manuf[:id] = _tmp_manufs.first.fetch(:id, nil)
                             _autopopulate_manuf[:match] = 1.0
                          end
                        end

                        if !_autopopulate_manuf.fetch(:id, nil)&.nonzero?
                          # the manufacturer is still not found, create it
                          _manuf_data = { :name => _autopopulate_manuf[:name],
                                          :slug => _autopopulate_manuf[:name].to_url }
                          if (_manuf_create_response = _nb.post('dcim/manufacturers/', _manuf_data.to_json, _nb_headers).body) &&
                             _manuf_create_response.is_a?(Hash)
                          then
                             _autopopulate_manuf[:id] = _manuf_create_response.fetch(:id, nil)
                             _autopopulate_manuf[:match] = 1.0
                          end
                        end

                        # at this point we *must* have the manufacturer ID
                        if _autopopulate_manuf.fetch(:id, nil)&.nonzero?

                          # make sure the desired device type also exists, look it up first
                          _query = { :offset => 0,
                                     :limit => 1,
                                     :manufacturer_id => _autopopulate_manuf[:id],
                                     :model => _autopopulate_default_dtype }
                          if (_dtypes_response = _nb.get('dcim/device-types/', _query).body) &&
                             _dtypes_response.is_a?(Hash) &&
                             (_tmp_dtypes = _dtypes_response.fetch(:results, [])) &&
                             (_tmp_dtypes.length() > 0)
                          then
                             _autopopulate_dtype = _tmp_dtypes.first
                          end

                          if _autopopulate_dtype.nil?
                            # the device type is not found, create it
                            _dtype_data = { :manufacturer => _autopopulate_manuf[:id],
                                            :model => _autopopulate_default_dtype,
                                            :slug => _autopopulate_default_dtype.to_url }
                            if (_dtype_create_response = _nb.post('dcim/device-types/', _dtype_data.to_json, _nb_headers).body) &&
                               _dtype_create_response.is_a?(Hash) &&
                               _dtype_create_response.has_key?(:id)
                            then
                               _autopopulate_dtype = _dtype_create_response
                            end
                          end

                          # # now we must also have the device type ID
                          if _autopopulate_dtype&.fetch(:id, nil)&.nonzero?

                            # create the device
                            _device_name = _autopopulate_hostname.to_s.empty? ? "#{_autopopulate_manuf[:name]} @ #{_key}" : "#{_autopopulate_hostname} @ #{_key}"
                            _device_data = { :name => _device_name,
                                             :device_type => _autopopulate_dtype[:id],
                                             :device_role => _autopopulate_drole[:id],
                                             :site => _autopopulate_site[:id],
                                             :status => "staged" }
                            if (_device_create_response = _nb.post('dcim/devices/', _device_data.to_json, _nb_headers).body) &&
                               _device_create_response.is_a?(Hash) &&
                               _device_create_response.has_key?(:id)
                            then
                               _autopopulate_device = _device_create_response
                            end

                          end # _autopopulate_dtype[:id] is valid

                        end # _autopopulate_manuf[:id] is valid

                      end # virtual machine vs. regular device

                    end # site and drole are valid

                  rescue Faraday::Error
                    # give up aka do nothing
                    _exception_error = true
                  end

                  if !_autopopulate_device.nil?
                    # we created a device, so send it back out as the result for the event as well
                    _devices << { :name => _autopopulate_device&.fetch(:name, _autopopulate_device&.fetch(:display, nil)),
                                  :id => _autopopulate_device&.fetch(:id, nil),
                                  :url => _autopopulate_device&.fetch(:url, nil),
                                  :site => _autopopulate_site&.fetch(:name, nil),
                                  :role => _autopopulate_drole&.fetch(:name, nil),
                                  :device_type => _autopopulate_dtype&.fetch(:name, nil),
                                  :manufacturer => _autopopulate_manuf&.fetch(:name, nil),
                                  :details => _verbose ? _autopopulate_device : nil }
                  end # _autopopulate_device was not nil (i.e., we autocreated a device)

                end # _autopopulate turned on and no results found

                _devices = collect_values(crush(_devices))
                _devices.fetch(:service, [])&.flatten!&.uniq!
                _lookup_result = _devices
              end # _lookup_type == :ip_device

              # this || is because we are going to need to do the VRF lookup if we're autopopulating
              # as well as if we're specifically requested to do that enrichment

              if (_lookup_type == :ip_vrf) || !_autopopulate_device.nil?
              #################################################################################
                # retrieve the list VRFs containing IP address prefixes containing the search key
                _vrfs = Array.new
                _query = { :contains => _key,
                           :offset => 0,
                           :limit => _page_size }
                _query[:site_n] = _lookup_site unless _lookup_site.nil? || _lookup_site.empty?
                begin
                  while true do
                    if (_prefixes_response = _nb.get('ipam/prefixes/', _query).body) &&
                       _prefixes_response.is_a?(Hash)
                    then
                      _tmp_prefixes = _prefixes_response.fetch(:results, [])
                      _tmp_prefixes.each do |p|
                        if (_vrf = p.fetch(:vrf, nil))
                          # non-verbose output is flatter with just names { :name => "name", :id => "id", ... }
                          # if _verbose, include entire object as :details
                          _vrfs << { :name => _vrf.fetch(:name, _vrf.fetch(:display, nil)),
                                     :id => _vrf.fetch(:id, nil),
                                     :site => ((_site = p.fetch(:site, nil)) && _site&.has_key?(:name)) ? _site[:name] : _site&.fetch(:display, nil),
                                     :tenant => ((_tenant = p.fetch(:tenant, nil)) && _tenant&.has_key?(:name)) ? _tenant[:name] : _tenant&.fetch(:display, nil),
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
                  _exception_error = true
                end
                _vrfs = collect_values(crush(_vrfs))
                _lookup_result = _vrfs unless (_lookup_type != :ip_vrf)
              end # _lookup_type == :ip_vrf

              if !_autopopulate_device.nil? && _autopopulate_device.fetch(:id, nil)&.nonzero?
                # device has been created, we need to create an interface for it
                _interface_data = { _autopopulate_manuf[:vm] ? :virtual_machine : :device => _autopopulate_device[:id],
                                    :name => "e0",
                                    :type => "other" }
                if !_autopopulate_mac.nil? && !_autopopulate_mac.empty?
                  _interface_data[:mac_address] = _autopopulate_mac.is_a?(Array) ? _autopopulate_mac.first : _autopopulate_mac
                end
                if !_vrfs.nil? && !_vrfs.empty?
                  _interface_data[:vrf] = _vrfs.fetch(:id, []).first
                end
                if (_interface_create_reponse = _nb.post(_autopopulate_manuf[:vm] ? 'virtualization/interfaces/' : 'dcim/interfaces/', _interface_data.to_json, _nb_headers).body) &&
                   _interface_create_reponse.is_a?(Hash) &&
                   _interface_create_reponse.has_key?(:id)
                then
                   _autopopulate_interface = _interface_create_reponse
                end

                if !_autopopulate_interface.nil? && _autopopulate_interface.fetch(:id, nil)&.nonzero?
                  # interface has been created, we need to create an IP address for it
                  _ip_data = { :address => "#{_key}/#{_key_ip&.prefix()}",
                               :assigned_object_type => _autopopulate_manuf[:vm] ? "virtualization.vminterface" : "dcim.interface",
                               :assigned_object_id => _autopopulate_interface[:id],
                               :status => "active" }
                  if (_vrf = _autopopulate_interface.fetch(:vrf, nil)) &&
                     (_vrf.has_key?(:id))
                  then
                    _ip_data[:vrf] = _vrf[:id]
                  end
                  if (_ip_create_reponse = _nb.post('ipam/ip-addresses/', _ip_data.to_json, _nb_headers).body) &&
                     _ip_create_reponse.is_a?(Hash) &&
                     _ip_create_reponse.has_key?(:id)
                  then
                     _autopopulate_ip = _ip_create_reponse
                  end
                end # check if interface was created and has ID

                if !_autopopulate_ip.nil? && _autopopulate_ip.fetch(:id, nil)&.nonzero?
                  # IP address was created, need to associate it as the primary IP for the device
                  _primary_ip_data = { _key_ip&.ipv6? ? :primary_ip6 : :primary_ip4 => _autopopulate_ip[:id] }
                  if (_ip_primary_reponse = _nb.patch("#{_autopopulate_manuf[:vm] ? 'virtualization/virtual-machines' : 'dcim/devices'}/#{_autopopulate_device[:id]}/", _primary_ip_data.to_json, _nb_headers).body) &&
                     _ip_primary_reponse.is_a?(Hash) &&
                     _ip_primary_reponse.has_key?(:id)
                  then
                     _autopopulate_device = _ip_create_reponse
                  end
                end # check if the IP address was created and has an ID

              end # check if device was created and has ID

              # yield return value for cache_hash getset
              _lookup_result
            }

  if !_result.nil? && _result.has_key?(:url) && !_result[:url]&.empty?
    _result[:url].map! { |u| u.delete_prefix(@netbox_url_base).gsub('/api/', '/') }
    if (_lookup_type == :ip_device) &&
       (!_result.has_key?(:device_type) || _result[:device_type]&.empty?) &&
       _result[:url].any? { |u| u.include? "virtual-machines" }
    then
      _result[:device_type] = [ "Virtual Machine" ]
    end
  end
  event.set("#{@target}", _result) unless _result.nil? || _result.empty?

  [event]
end

def mac_string_to_integer(string)
  string.tr('.:-','').to_i(16)
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