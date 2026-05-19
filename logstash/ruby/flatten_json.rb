def register(params)
  @src_field = params["source_field"]
  @dst_field = params["target_field"]
end

def filter(event)
  def flatten_tree(node, path_prefix = "", result = [])
    case node
    when Hash
      node.each do |k, v|
        path = path_prefix.empty? ? k.to_s : "#{path_prefix}.#{k}"
        flatten_tree(v, path, result)
      end
    when Array
      node.each_with_index do |v, i|
        path = "#{path_prefix}.#{i}"
        flatten_tree(v, path, result)
      end
    else
      result << { "path" => path_prefix, "value" => node }
    end
    result
  end

  src = event.get(@src_field)
  if src
    flat = flatten_tree(src)
    event.set(@dst_field, flat)
  end
  [event]
end