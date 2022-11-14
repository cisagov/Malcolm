def concurrency
  :shared
end

def register(params)
  require 'lru_redux'
  require 'rest-client'

  @source = params["source"]
  @target = params["target"]
  @netbox_url = params.fetch("netbox_url", "http://netbox:8080/netbox/api/")
  @netbox_token = params["netbox_token"]
  @netbox_token_env = params["netbox_token_env"]
  if @netbox_token.nil? and !@netbox_token_env.nil?
    @netbox_token = ENV[@netbox_token_env]
  end
  @CacheHash = Hash.new{ LruRedux::ThreadSafeCache.new(params.fetch("cache_size", 500)) }
end

def filter(event)
  _key = event.get("#{@source}")
  if _key.nil?
    return [event]
  end

  _results = RestClient.get(@netbox_url,
    {
      :Authorization => "Token " + @netbox_token
    })

  event.set("#{@target}", _results)

  [event]
end


###############################################################################
# tests

###############################################################################