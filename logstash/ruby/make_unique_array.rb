def concurrency
  :shared
end

def register(params)
  @field = params["field"]
  _prune = params["prune"]
  if !_prune.is_a?(Array) then
    _newPrune = Array.new
    _newPrune.push(_prune) unless _prune.nil?
    _prune = _newPrune
  end
  @prune = _prune
end

def filter(event)
  _vals = event.get("#{@field}")
  if !_vals.nil? then
    if !_vals.is_a?(Array) then
      _newVals = Array.new
      _newVals.push(_vals)
      _vals = _newVals
    end
    event.set("#{@field}", _vals.uniq.reject {|x| @prune.include? x})
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

test "array needs prune" do
  parameters do
    { "field" => "sourcefield", "prune" => "x" }
  end

  in_event { { "sourcefield" => [ "a", "b", "a", "x" ] } }

  expect("result to be equal") do |events|
    events.first.get("sourcefield").length == 2
  end
end

test "array needs prune from array" do
  parameters do
    { "field" => "sourcefield", "prune" => [ "y", "z" ] }
  end

  in_event { { "sourcefield" => [ "a", "b", "a", "x", "y", "z" ] } }

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