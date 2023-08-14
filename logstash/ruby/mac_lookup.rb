def concurrency
  :shared
end

def register(params)
  require 'psych'

  @source = params["source"]
  @target = params["target"]
  if File.exist?(params["map_path"])
    @macarray = Array.new
    psych_load_yaml(params["map_path"]).each do |mac|
      @macarray.push([mac_string_to_integer(mac['low']), mac_string_to_integer(mac['high']), mac['name']])
    end
    # Array.bsearch only works on a sorted array
    @macarray.sort_by! { |k| [k[0], k[1]]}
  else
    @macarray = nil
  end
  @macregex = Regexp.new(/\A([0-9a-fA-F]{2}[-:.]){5}([0-9a-fA-F]{2})\z/)
end

def filter(event)
  _mac = event.get("#{@source}")
  if _mac.nil? or @macarray.nil?
    return [event]
  end

  _names = Array.new

  case _mac
  when String
    if @macregex.match?(_mac)
      _macint = mac_string_to_integer(_mac)
      _vendor = @macarray.bsearch{ |_vendormac| (_macint < _vendormac[0]) ? -1 : ((_macint > _vendormac[1]) ? 1 : 0)}
      _names.push(_vendor[2]) unless _vendor.nil?
    end
  when Array
    _mac.each do |_addr|
      if @macregex.match?(_addr)
        _macint = mac_string_to_integer(_addr)
        _vendor = @macarray.bsearch{ |_vendormac| (_macint < _vendormac[0]) ? -1 : ((_macint > _vendormac[1]) ? 1 : 0)}
        _names.push(_vendor[2]) unless _vendor.nil?
      end
    end
  end

  _names = _names.uniq
  if _names.length > 1
    event.set("#{@target}", _names)
  elsif _names.length > 0
    event.set("#{@target}", _names.first)
  end

  [event]
end

def mac_string_to_integer(string)
  string.tr('.:-','').to_i(16)
end

def psych_load_yaml(filename)
  parser = Psych::Parser.new(Psych::TreeBuilder.new)
  parser.code_point_limit = 64*1024*1024
  parser.parse(IO.read(filename, :mode => 'r:bom|utf-8'))
  yaml_obj = Psych::Visitors::ToRuby.create().accept(parser.handler.root)
  if yaml_obj.is_a?(Array) && (yaml_obj.length() == 1)
    yaml_obj.first
  else
    yaml_obj
  end
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