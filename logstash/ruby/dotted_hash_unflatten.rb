def concurrency
  :shared
end

def register(params)
  @source = params["source"]
  @target = params["target"]
end

def filter(event)
  _sourcehash = event.get("#{@source}")
  if _sourcehash.nil? or (_sourcehash.length == 0)
    return [event]
  end

  _desthash = Hash.new
  _sourcehash.each do |key, value|
    _desthash = merge_recursively(_desthash, unflatten(key.split('.'), value))
  end
  event.set("#{@target}", _desthash)

  [event]
end

def unflatten(arr, value)
  if arr.empty?
    value
  else
    {}.tap do |hash|
      hash[arr.shift] = unflatten(arr, value)
    end
  end
end

def merge_recursively(a, b)
  a.merge(b) {|key, a_item, b_item| merge_recursively(a_item, b_item) }
end

###############################################################################
# tests

test "standard flow" do
  parameters do
    { "source" => "sourcefield", "target" => "targetfield" }
  end

  in_event { { "sourcefield" => {"eth0.rx.bytes"=>98, "eth0.rx.packets"=>1, "eth0.rx.errors"=>0, "eth0.tx.bytes"=>98, "eth0.tx.packets"=>1, "eth0.tx.errors"=>0} } }

  expect("unflattened") do |events|
    (events.first.get("targetfield")["eth0"]["rx"].length == 3) and (events.first.get("targetfield")["eth0"]["tx"].length == 3)
  end
end
###############################################################################