def concurrency
  :shared
end

def register(params)
  @source = params["source"]
  @host = params["host"]
  @share = params["share"]
  @path = params["path"]
end

def filter(event)
  _value = event.get("#{@source}")
  if _value.nil? or !_value.is_a?(String)
    return [event]

  # yuck...                        host starting with \\ (optional)
  #                                v
  #                                               share starting with \ and optionally ending with $ (optional)
  #                                               v
  #                                                                       path is everything else
  #                                                                       v
  elsif parts = _value.match(/^\s*(\\\\[^\\\/]+)?(\\[^\\\/\$]+\$?)?[\\\/]?(.*)$/) then
    host, share, path = parts.captures
    host = host.delete_prefix('\\\\') unless host.to_s.empty?
    share = share.delete_prefix('\\').delete_suffix('$') unless share.to_s.empty?
    event.set("#{@host}", host) unless host.to_s.empty?
    event.set("#{@share}", share) unless share.to_s.empty?
    event.set("#{@path}", path) unless path.to_s.empty?
  end

  [event]
end

###############################################################################
# tests
