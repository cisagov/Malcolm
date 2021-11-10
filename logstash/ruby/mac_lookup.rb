def concurrency
  :shared
end

def register(params)
  @source = params["source"]
  @target = params["target"]
  if File.exist?(params["map_path"])
    @macmap = Hash.new
    YAML.load(File.read(params["map_path"])).each do |mac|
      _low = mac_string_to_integer(mac['low'])
      _high = mac_string_to_integer(mac['high'])
      @macmap[(_low.._high)] = mac['name']
    end
  else
    @macmap = nil
  end
  @macregex = Regexp.new(/\A([0-9a-fA-F]{2}[-:.]){5}([0-9a-fA-F]{2})\z/)
end

def filter(event)
  _mac = event.get("#{@source}")
  if _mac.nil? or @macmap.nil?
    return [event]
  end

  _names = Array.new

  case _mac
  when String
    if @macregex.match?(_mac)
      _name = @macmap.find{|key, value| key === mac_string_to_integer(_mac)}&.[](1)
      _names.push(_name) unless _name.nil?
    end
  when Array
    _mac.each do |_addr|
      if @macregex.match?(_addr)
        _name = @macmap.find{|key, value| key === mac_string_to_integer(_addr)}&.[](1)
        _names.push(_name) unless _name.nil?
      end
    end
  end

  _names = _names.uniq
  if _names.length > 1
    event.set("#{@target}", _names)
  elsif if _names.length > 0
    event.set("#{@target}", _names.first)
  end

  [event]
end

def mac_string_to_integer(string)
  string.tr('.:-','').to_i(16)
end

###############################################################################
# tests

test "standard flow" do
  parameters do
    { "source" => "sourcefield", "target" => "targetfield", "map_path" => "/etc/ics_macs.yaml" }
  end

  in_event { { "sourcefield" => "00:50:C2:7A:50:01" } }

  expect("result to be equal") do |events|
    events.first.get("targetfield") == "Quantum Medical Imaging"
  end
end

test "not in map" do
  parameters do
    { "source" => "sourcefield", "target" => "targetfield", "map_path" => "/etc/ics_macs.yaml" }
  end

  in_event { { "sourcefield" => "DE:AD:ED:BE:EE:EF" } }

  expect("targetfield not set") do |events|
    events.first.get("targetfield").nil?
  end
end

test "bad input string" do
  parameters do
    { "source" => "sourcefield", "target" => "targetfield", "map_path" => "/etc/ics_macs.yaml" }
  end

  in_event { { "sourcefield" => "not a mac address" } }

  expect("targetfield not set") do |events|
    events.first.get("targetfield").nil?
  end
end

test "missing field" do
  parameters do
    { "source" => "sourcefield", "target" => "targetfield", "map_path" => "/etc/ics_macs.yaml" }
  end

  in_event { { } }

  expect("targetfield not set") do |events|
    events.first.get("targetfield").nil?
  end
end
###############################################################################