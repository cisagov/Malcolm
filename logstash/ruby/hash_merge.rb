def concurrency
  :shared
end

def register(params)
  @source = params["source"]
  @target = params["target"]
end

def filter(event)
  _src = event.get("#{@source}")
  if _src.nil?
    return [event]
  elsif !_src.is_a?(Hash) then
    event.tag("_rubyexception")
    return [event]
  end

  _dst = event.get("#{@target}")
  if _dst.nil? then
    _dst = Hash.new
  elsif !_dst.is_a?(Hash) then
    event.tag("_rubyexception")
    return [event]
  end

  _dst.deep_merge(_src)
  event.set("#{@target}", _dst)

  [event]
end

class ::Hash
  def deep_merge(second)
    merger = proc { |key, v1, v2| Hash === v1 && Hash === v2 ? v1.merge(v2, &merger) : v2 }
    self.merge(second, &merger)
  end
end

###############################################################################
# tests

###############################################################################