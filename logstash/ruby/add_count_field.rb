def concurrency
  :shared
end

def register(params)
  @source = params["source"]
  @target = params["target"]
end

def filter(event)
  _vals = event.get("#{@source}")
  if !_vals.nil? then
    if _vals.is_a?(Array) || _vals.is_a?(Hash) then
      event.set("#{@target}", _vals.length)
    else
      event.set("#{@target}", 1)
    end
  end
  [event]
end

###############################################################################
# tests

test "array count" do
  parameters do
    { "source" => "sourcefield", "target" => "targetfield"}
  end

  in_event { { "sourcefield" => [ "a", "b", "a" ] } }

  expect("array test") do |events|
    events.first.get("[targetfield]") == 3
  end
end

test "hash count" do
  parameters do
    { "source" => "sourcefield", "target" => "targetfield"}
  end

  in_event { { "sourcefield" => { "foo" => 1, "bar" => "wockawocka" } } }

  expect("hash test") do |events|
    events.first.get("[targetfield]") == 2
  end
end

test "string count" do
  parameters do
    { "source" => "sourcefield", "target" => "targetfield"}
  end

  in_event { { "sourcefield" => "sufjan stevens" } }

  expect("string test") do |events|
    events.first.get("[targetfield]") == 1
  end
end

test "int count" do
  parameters do
    { "source" => "sourcefield", "target" => "targetfield"}
  end

  in_event { { "sourcefield" => 99 } }

  expect("int test") do |events|
    events.first.get("[targetfield]") == 1
  end
end

###############################################################################

