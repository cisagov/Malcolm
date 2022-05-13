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
  _map = params["translate"]
  if _map.is_a?(Hash) then
    @translate = _map
  else
    @translate = Hash.new
  end
end

def filter(event)
  _vals = event.get("#{@field}")
  if !_vals.nil? then
    if !_vals.is_a?(Array) then
      _newVals = Array.new
      _newVals.push(_vals)
      _vals = _newVals
    end
    #                            v dedupe
    #                            |    v prune unwanted values       v translate values when applicable
    #                            |    |                             |                           v keep if not in translate hash
    event.set("#{@field}", _vals.uniq.reject{|x| @prune.include? x}.map{|y| @translate.fetch(y, y) })
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

test "translate" do
  parameters do
    { "field" => "sourcefield", "translate" => { "a" => "alpha",
                                                 "c" => "charlie" } }
  end

  in_event { { "sourcefield" => [ "a", "b", "c" ] } }

  expect("result to be equal") do |events|
    Array(events.first.get("sourcefield")).to_set == ["alpha", "b", "charlie"].to_set
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