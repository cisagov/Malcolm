def concurrency
  :shared
end

def register(params)
  require 'lru_redux'
  require 'rest-client'
  require 'date'

  # source field containing lookup value
  @source = params["source"]

  # source field name for caching (may be different than "source",
  #   e.g. "source" could be source.ip_two and "source_cache" could be source.ip)
  @source_cache = params["source_cache"]
  if @source_cache.nil? and !@source.nil?
    @source_cache = @source
  end

  # caching parameters
  @cache_size = params.fetch("cache_size", 500)
  @cache_ttl = params.fetch("cache_ttl", 300)

  # target field to store looked-up value
  @target = params["target"]

  # connection URL for netbox
  @netbox_url = params.fetch("netbox_url", "http://netbox:8080/netbox/api/")

  # connection token (either specified directly or read from ENV via netbox_token_env)
  @netbox_token = params["netbox_token"]
  @netbox_token_env = params["netbox_token_env"]
  if @netbox_token.nil? and !@netbox_token_env.nil?
    @netbox_token = ENV[@netbox_token_env]
  end

  # hash of field names (from source_cache), each of which contains the respective looked-up values
  @cache_hash = LruRedux::ThreadSafeCache.new(params.fetch("fields_cache_size", 4096))
end

def filter(event)
  _key = event.get("#{@source}")
  if _key.nil?
    return [event]
  end

  # TODO: what if RestClient returns nil (which it will often)... is there a way to *not* store it if it contains nil?
  _result = @cache_hash.getset(@source_cache){
              LruRedux::TTL::ThreadSafeCache.new(@cache_size, @cache_ttl)
            }.getset(_key){
              RestClient.get(@netbox_url,
                             { "Authorization" => "Token " + @netbox_token })}

  event.set("#{@target}", _result) unless _result.nil?

  [event]
end


###############################################################################
# tests

###############################################################################