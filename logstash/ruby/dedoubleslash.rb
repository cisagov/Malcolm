def concurrency
  :shared
end

def register(params)
  @source = params["source"]
  @target = params["target"]
end

def filter(event)
  _value = event.get("#{@source}")
  if _value.nil?
    return [event]
  end

  _fixed = Array.new

  case _value
  when String
    _fixed.push(_value.gsub(/\\\\/,'\\'))
  when Array
    _value.each do |_val|
      _fixed.push(_val.gsub(/\\\\/,'\\'))
    end
  end

  if _fixed.length > 1
    event.set("#{@target}", _fixed)
  elsif _fixed.length > 0
    event.set("#{@target}", _fixed.first)
  end

  [event]
end

###############################################################################
# tests

test "standard flow" do
  parameters do
    { "source" => "sourcefield", "target" => "targetfield" }
  end

  in_event { { "sourcefield" => "Public\\\\Pictures\\\\Sample Pictures\\\\desktop.ini" } }

  expect("result to be equal") do |events|
    events.first.get("targetfield") == "Public\\Pictures\\Sample Pictures\\desktop.ini"
  end
end