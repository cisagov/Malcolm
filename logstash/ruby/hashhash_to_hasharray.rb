def concurrency
  :shared
end

def register(params)
  @source = params["source"]
  @target_hash_array = params["target_hash_array"]
  @target_keys_array = params["target_keys_array"]
  _name_key = params["name_key"]
  if _name_key.is_a?(String) and !_name_key.empty? then
    @name_key = _name_key
  else
    @name_key = "key"
  end

end

def filter(event)
  _source_hash = event.get("#{@source}")
  if !_source_hash.nil? and _source_hash.is_a?(Hash) then
    event.set("#{@target_keys_array}", _source_hash.keys) unless @target_keys_array.nil? or @target_keys_array.empty?
    event.set("#{@target_hash_array}", _source_hash.map { |k, v| v.merge(@name_key => k) }) unless @target_hash_array.nil? or @target_hash_array.empty?
  end
  [event]
end

###############################################################################
# tests

test "remove field keys with nil values" do

  parameters do
    { "source" => "sourcefield", "target_hash_array" => "hash", "target_keys_array" => "keys", "name_key" => "name" }
  end

  in_event { { "sourcefield" => { "bob" => { "age" => 40, "weight" => 200}, "jane" => { "age" => 39, "weight" => 150 } } } }

  expect("return a single event") do |events|
    events.size == 1
  end

  expect("hash is the right type") do |events|
    events.first.get("hash").is_a?(Array)
  end

  expect("hash is the right length") do |events|
    events.first.get("hash").length == 2
  end

  expect("bob exists") do |events|
    events.first.get("[hash]").select {|entry| entry["name"] == "bob"}.length == 1
  end

  expect("jane exists") do |events|
    events.first.get("[hash]").select {|entry| entry["name"] == "jane"}.length == 1
  end

  expect("bob is right") do |events|
    events.first.get("[hash]").select {|entry| entry["name"] == "bob"}[0]["age"] == 40
  end

  expect("jane is right") do |events|
    events.first.get("[hash]").select {|entry| entry["name"] == "jane"}[0]["age"] == 39
  end

  expect("keys is the right type") do |events|
    events.first.get("keys").is_a?(Array)
  end

  expect("keys is the right length") do |events|
    events.first.get("keys").length == 2
  end

  expect("keys is right") do |events|
    events.first.get("keys").include?("bob") and events.first.get("keys").include?("jane")
  end

end
