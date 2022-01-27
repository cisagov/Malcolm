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
    host = host.delete_prefix('\\\\') unless host.nil?
    share = share.delete_prefix('\\').delete_suffix('$') unless share.nil?
    event.set("#{@host}", host) unless host.nil? or (host.length == 0)
    event.set("#{@share}", share) unless share.nil? or (share.length == 0)
    event.set("#{@path}", path) unless path.nil? or (path.length == 0)
  end

  [event]
end

###############################################################################
# tests
