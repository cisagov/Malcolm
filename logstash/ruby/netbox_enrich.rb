def concurrency
  :shared
end

def register(params)
  require 'lru_redux'
  require 'netbox-client-ruby'

  @source = params["source"]
  @target = params["target"]
  @netbox_url = params.fetch("netbox_url", "http://netbox:9001/api/")
  @netbox_token = params["netbox_token"]
  @netbox_token_env = params["netbox_token_env"]
  if @netbox_token.nil? and !@netbox_token_env.nil?
    @netbox_token = ENV[@netbox_token_env]
  end
  @cache_size = params.fetch("cache_size", 500)

  # TODO: are these thread-safe?
  @CacheHash = Hash.new{ LruRedux::Cache.new(@cache_size) }
  NetboxClientRuby.configure do |c|
    c.netbox.auth.token = @netbox_token
    c.netbox.api_base_url = @netbox_url
  end
end

def filter(event)
  _key = event.get("#{@source}")
  if _key.nil?
    return [event]
  end

  _results = NetboxClientRuby.dcim.sites
  _results = _results.uniq

  if _results.length > 1
    event.set("#{@target}", _results)
  elsif _results.length > 0
    event.set("#{@target}", _results.first)
  end

  [event]
end


###############################################################################
# tests

###############################################################################