def concurrency
  :shared
end

def register(params)
  require 'lru_reredux'
  require 'net/http'
  require 'cgi'

  @freq_lookup_enabled = ((ENV['FREQ_LOOKUP'] || 'false').downcase == 'true')

  # connection URL for freq
  @freq_url = params.fetch("freq_url", "http://freq:10004/measure").chomp("/")

  # source field containing lookup value
  @source = params["source"]

  # type of value being looked up (e.g., dns, tls, etc.)
  @source_type = params["source_type"].to_s.downcase
  if @source_type.nil? || @source_type.empty?
    @source_type = "other"
  end

  # targets field to store calculated values (two algorithms/calculations are done by freq)
  @target_1 = params["target_1"]
  @target_2 = params["target_2"]

  # size of hash of source types
  @source_type_cache_size = params.fetch("source_type_cache_size", 10)

  # size of hash of individual queries within source types
  @cache_size = params.fetch("cache_size", 2048)

  # hash of source_types
  @source_type_hash = LruReredux::ThreadSafeCache.new(@source_type_cache_size)
end

def filter(event)
  if not @freq_lookup_enabled
    return [event]
  end

  _vals = event.get("#{@source}")
  if _vals.nil?
    return [event]
  end

  _vals = [_vals] unless _vals.is_a?(Array)

  _scores_v1 = Array.new
  _scores_v2 = Array.new
  _scores_tmp = Array.new
  begin
    _vals.each { |_query|
      if (_query.length >= 4) and (_query !~ /(ip6\.int|ip6\.arpa|in-addr\.arpa|b32\.i2p)$/i) then
        _scores_tmp = @source_type_hash.getset(@source_type){
          LruReredux::ThreadSafeCache.new(@cache_size)
        }.getset(_query){
          Net::HTTP.get_response(URI.parse(@freq_url + '/' + CGI.escape(_query))).body.gsub(/(^\(|\)$|\s+)/, '').split(',').map(&:to_f)
        }
        if (_scores_tmp.length == 2) then
          _scores_v1 << _scores_tmp[0]
          _scores_v2 << _scores_tmp[1]
        end
      end
    }
  rescue Exception => _e
    event.set('ruby_exception', 'ruby_dns_freq_lookup: ' + _e.message)
  end
  event.set("#{@target_1}", _scores_v1) unless _scores_v1.empty?
  event.set("#{@target_2}", _scores_v2) unless _scores_v2.empty?

  [event]
end


###############################################################################
# tests

###############################################################################