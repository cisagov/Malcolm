def concurrency
  :shared
end

def register(params)
  @field = params["field"]
end

def filter(event)
  _vals = event.get(@field)
  if !_vals.nil? then
    if !_vals.is_a?(Array) then
      _newVals = Array.new
      _newVals.push(_vals)
      _vals = _newVals
    end
    event.set(@field, _vals.uniq)
  end
  [event]
end

###############################################################################
# tests

test "array has duplicates" do
  parameters do
    { "field" => "sourcefield" }
  end

  in_event { { "sourcefield" => [ "a", "b", "a" ] } }

  expect("result to be equal") do |events|
    events.first.get("sourcefield").length == 2
  end
end

test "has no duplicates" do
  parameters do
    { "field" => "sourcefield" }
  end

  in_event { { "sourcefield" => [ "a", "b", "c" ] } }

  expect("result to be equal") do |events|
    events.first.get("sourcefield").length == 3
  end
end

test "not an array" do
  parameters do
    { "field" => "sourcefield" }
  end

  in_event { { "sourcefield" => "a" } }

  expect("result to be equal") do |events|
    events.first.get("sourcefield").length == 1
  end
end

###############################################################################