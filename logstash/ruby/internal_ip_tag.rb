def concurrency
  :shared
end

require 'ipaddr'
require 'lru_reredux'

def register(params)
  @field = params["field"].to_s                               # e.g., "[source][ip]" or "[destination][ip]"
  @tag   = params["tag"].to_s                                 # e.g., "internal_source" or "internal_destination"
  @network_type_target = params["network_type_target"].to_s   # e.g., "[network][type]"

  _networks = [
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
    "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
    "255.255.255.255/32", "::/0", "::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8"
  ]
  # Split IPv4 vs IPv6 CIDRs
  @internal_cidrs_ipv4 = []
  @internal_cidrs_ipv6 = []
  _networks.each do |n|
    ip = IPAddr.new(n)
    if ip.ipv4?
      @internal_cidrs_ipv4 << ip
    else
      @internal_cidrs_ipv6 << ip
    end
  end

  # Thread-safe LRU cache: key = IP string, value = boolean for internal
  @ip_cache = LruReredux::ThreadSafeCache.new(10000, true)
end


def filter(event)
  ip_str = event.get("#{@field}")
  return [event] unless ip_str

  internal, ip_class = @ip_cache.getset(ip_str) {
    begin
      ip_obj = IPAddr.new(ip_str)
      ip_is_v6 = ip_obj.ipv6?
      cidrs_to_check = ip_is_v6 ? @internal_cidrs_ipv6 : @internal_cidrs_ipv4
      [cidrs_to_check.any? { |cidr| cidr.include?(ip_obj) }, ip_is_v6 ? "ipv6" : "ipv4"]
    rescue
      [ false, "" ]
    end
  }

  event.tag(@tag) if internal && !@tag.empty?
  event.set("#{@network_type_target}", ip_class) unless ip_class.empty? || @network_type_target.empty?

  [event]
end

# ###############################################################################
# # tests

# test "tag internal source IPs" do
#   parameters do
#     { "field" => "[source][ip]", "tag" => "internal_source" }
#   end

#   in_event { { "source" => { "ip" => "10.1.2.3" }, "destination" => { "ip" => "8.8.8.8" } } }
#   in_event { { "source" => { "ip" => "192.168.1.100" }, "destination" => { "ip" => "172.16.5.10" } } }
#   in_event { { "source" => { "ip" => "203.0.113.5" }, "destination" => { "ip" => "198.51.100.7" } } }
#   in_event { { "source" => { "ip" => "2001:db8::1" }, "destination" => { "ip" => "fc00::1234" } } }

#   expect("internal source IPs are tagged") do |events|
#     events.all? do |e|
#       ip = e.get("[source][ip]")
#       tags = e.get("tags") || []

#       case ip
#       when "10.1.2.3", "192.168.1.100"
#         tags.include?("internal_source")
#       when "203.0.113.5", "2001:db8::1"
#         !tags.include?("internal_source")
#       else
#         true
#       end
#     end
#   end

#   expect("events array is preserved") do |events|
#     events.size == 4
#   end
# end


# test "tag internal destination IPs" do
#   parameters do
#     { "field" => "[destination][ip]", "tag" => "internal_destination" }
#   end

#   in_event { { "source" => { "ip" => "8.8.8.8" }, "destination" => { "ip" => "10.2.3.4" } } }
#   in_event { { "source" => { "ip" => "172.20.1.1" }, "destination" => { "ip" => "192.168.5.6" } } }
#   in_event { { "source" => { "ip" => "203.0.113.5" }, "destination" => { "ip" => "198.51.100.7" } } }
#   in_event { { "source" => { "ip" => "2001:db8::1" }, "destination" => { "ip" => "fc00::abcd" } } }

#   expect("internal destination IPs are tagged") do |events|
#     events.all? do |e|
#       ip = e.get("[destination][ip]")
#       tags = e.get("tags") || []

#       case ip
#       when "10.2.3.4", "192.168.5.6", "fc00::abcd"
#         tags.include?("internal_destination")
#       when "198.51.100.7"
#         !tags.include?("internal_destination")
#       else
#         true
#       end
#     end
#   end

#   expect("events array is preserved") do |events|
#     events.size == 4
#   end
# end
