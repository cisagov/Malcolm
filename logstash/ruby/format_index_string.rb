def concurrency
  :shared
end

def register(params)
  require 'time'

  @prefix = params["prefix"]
  _prefix_env = params["prefix_env"]
  if @prefix.nil? && !_prefix_env.nil?
    @prefix = ENV[_prefix_env]
  end
  if !@prefix.nil? && @prefix.empty?
    @prefix = params["prefix_default"]
  end

  @suffix = params["suffix"]
  _suffix_env = params["suffix_env"]
  if @suffix.nil? && !_suffix_env.nil?
    @suffix = ENV[_suffix_env]
  end
  if !@suffix.nil? && @suffix.empty?
    @suffix = params["suffix_default"]
  end

  _midfix_fields = params["midfix_fields"]
  if !_midfix_fields.nil? then
    if _midfix_fields.is_a?(Array) then
      @midfix = _midfix_fields
    else
      @midfix = Array.new
      if !_midfix_fields.empty?
        @midfix.push(_midfix_fields)
      end
    end
  else
    @midfix = Array.new
  end

  @target = params["target"]
end

def filter(event)

  event_time = event.get("[@timestamp]")
  if !event_time.nil? then
    tstamp = Time.at(event_time.to_i).utc
  else
    tstamp = Time.now.utc
  end

  prefix_resolved = @prefix.delete_suffix('*')
  if prefix_resolved[-1].count("^a-z0-9").zero? then
    suffix_separator = ''
  else
    suffix_separator = prefix_resolved[-1]
    prefix_resolved = prefix_resolved[0..-2]
  end

  suffix_resolved = @suffix
  # first handle field substitution in {{ }}
  if parts = suffix_resolved.scan(/({{([^}]+)}})/) then
      if parts.kind_of?(Array) then
          parts.each do |pair|
              if pair.kind_of?(Array) and (pair.length > 0) then
                  bracketed_field_name = pair[1].gsub(/\s+/, '').split('.').map { |part| "[#{part}]" }.join
                  suffix_resolved =
                    suffix_resolved.sub(pair[0],
                                        event.get("#{bracketed_field_name}").to_s.downcase.gsub(/[^a-z0-9_\-]/, '').gsub(/^[\-_]+/, ''))
              end
          end
      end
  end

  # now handle timestamp substitution in %{}
  if parts = suffix_resolved.scan(/(%{([^}]+)})/) then
      if parts.kind_of?(Array) then
          parts.each do |pair|
              if pair.kind_of?(Array) and (pair.length > 0) then
                  suffix_resolved = suffix_resolved.sub(pair[0], tstamp.strftime(pair[1]))
              end
          end
      end
  end

  midfix_first = nil
  @midfix.each do |field|
    midfix_first = event.get("#{field}")
    if !midfix_first.nil? && !midfix_first.empty?
      midfix_first = '_' + midfix_first
      break
    end
  end

  event.set("#{@target}", (prefix_resolved + String(midfix_first) + suffix_separator + suffix_resolved).downcase)

  [event]
end
