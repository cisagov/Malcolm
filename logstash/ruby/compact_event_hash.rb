def concurrency
  :shared
end

require 'set'

# precompute discardable strings for O(1) lookups
PLACEHOLDER_STRINGS = Set.new(["", "-", "?", "(empty)", "(none)", "(null)", "NULL", "unset", "Nul"]).freeze
ZERO_STRINGS        = Set.new(["0", "0x0"]).freeze

def register(params)
  @field = params["field"]
  # whether to discard zero/falsey numeric/string values
  _discard_zeroes_str = params["discard_zeroes"]
  @discard_zeroes = [1, true, '1', 'true', 't', 'on', 'enabled'].include?(_discard_zeroes_str.to_s.downcase)
end

def compact_in_place!(h)
  case h
  when Hash
    h.each do |k, v|
      remove = case v
      when Hash
        compact_in_place!(v)
        v.empty?
      when Array
        v.delete_if do |e|
          case e
          when Hash, Array
            compact_in_place!(e)
            e.empty?
          when String
            discard_string?(e)
          when Numeric
            @discard_zeroes && e.zero?
          when NilClass
            true
          else
            false
          end
        end
        v.empty?
      when String
        discard_string?(v)
      when Numeric
        @discard_zeroes && v.zero?
      when NilClass
        true
      else
        false
      end
      h.delete(k) if remove
    end
  when Array
    h.delete_if do |e|
      case e
      when Hash, Array
        compact_in_place!(e)
        e.empty?
      when String
        discard_string?(e)
      when Numeric
        @discard_zeroes && e.zero?
      when NilClass
        true
      else
        false
      end
    end
  end
  h
end

# helper to check strings for discardable values
def discard_string?(s)
  return false unless s.is_a?(String)
  PLACEHOLDER_STRINGS.include?(s) || (@discard_zeroes && ZERO_STRINGS.include?(s))
end

def filter(event)
  _hashfield = event.get("#{@field}")
  if _hashfield.is_a?(Hash)
    compact_in_place!(_hashfield)
    event.set("#{@field}", _hashfield)
  end
  [event]
end

###############################################################################
# tests

test "remove field keys with nil values" do

  parameters do
    { "field" => "nested" }
  end

  in_event { { "name" => "eleanor rigby", "age" => 59, "nested" => { "foo" => 1, "bar" => nil, "blat" => "-", "blarg" => "(empty)", "biz" => "yo" }} }

  expect("return a single event") do |events|
    events.size == 1
  end

  expect("kept the [name] key") do |events|
    events.first.get("[name]") == "eleanor rigby"
  end

  expect("kept the [age] key") do |events|
    events.first.get("[age]") == 59
  end

  expect("kept the [nested][foo] key") do |events|
    events.first.get("[nested][foo]") == 1
  end

  expect("kept the [nested][biz] key") do |events|
    events.first.get("[nested][biz]") == "yo"
  end

  expect("remove the bar key") do |events|
    !events.first.include?("[nested][bar]")
  end

  expect("remove the blat key") do |events|
    !events.first.include?("[nested][blat]")
  end

  expect("remove the blarg key") do |events|
    !events.first.include?("[nested][blarg]")
  end

end


test "call on non-hash field type" do

  parameters do
    { "field" => "name" }
  end

  in_event { { "name" => "eleanor rigby", "age" => 59 } }

  expect("return a single event") do |events|
    events.size == 1
  end

  expect("kept the [name] key") do |events|
    events.first.get("[name]") == "eleanor rigby"
  end

  expect("kept the [age] key") do |events|
    events.first.get("[age]") == 59
  end

end