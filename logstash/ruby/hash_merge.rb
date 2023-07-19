def concurrency
  :shared
end

def register(params)
  require 'deep_merge'

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

  _dst.deep_merge!(_src)
  event.set("#{@target}", _dst)

  [event]
end


###############################################################################
# tests

test "merged with overwrite" do
  parameters do
    { "source" => "sourcefield", "target" => "targetfield" }
  end

  in_event { { "targetfield" => {"host"=>{"name" => "before"}, "foo"=>"bar"}, "sourcefield" => {"host"=>{"name" => "after"}, "bumble"=>"bee"} } }

  expect("merged_with_overwrite") do |events|
    (events.first.get("targetfield")["host"]["name"] == "after") and (events.first.get("targetfield")["foo"] == "bar") and (events.first.get("targetfield")["bumble"] == "bee")
  end
end

test "merged without overwrite" do
  parameters do
    { "source" => "sourcefield", "target" => "targetfield" }
  end

  in_event { { "targetfield" => {"host"=>{"name" => "roland"}, "foo"=>"bar"}, "sourcefield" => {"host"=>{"surname" => "deschain"}, "bumble"=>"bee"} } }

  expect("merged_with_overwrite") do |events|
    (events.first.get("targetfield")["host"]["name"] == "roland") and (events.first.get("targetfield")["host"]["surname"] == "deschain") and (events.first.get("targetfield")["foo"] == "bar") and (events.first.get("targetfield")["bumble"] == "bee")
  end
end
###############################################################################