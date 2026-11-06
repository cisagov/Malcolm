# Run the production filter with a deterministic, in-memory NetBox API.
# Optional gems are stubbed only at their loading boundary; the identity,
# creation, pagination, filter cache and synchronization methods run unchanged.
require 'json'
require 'ipaddr'
require 'thread'
%w[faraday fuzzystringmatch lru_reredux stringex_lite].each { |name| $LOADED_FEATURES << "#{name}.rb" }
module Faraday
  class Error < StandardError; end
end
module Concurrent
  Map = Hash
  class AtomicFixnum
    def initialize(*); end
  end
end
class FakeCache < Hash
  def initialize(*); super(); end
  def getset(key)
    self[key] = yield unless key?(key)
    self[key]
  end
end
module LruReredux
  ThreadSafeCache = FakeCache
  module TTL
    ThreadSafeCache = FakeCache
  end
end
class IdentityFilter
  class_eval(File.read(ARGV.fetch(0)), ARGV.fetch(0))
  def initialize
    { :netbox_enabled => true, :autopopulate => true, :lookup_type => :ip_device,
      :target => '[source][device]', :source => '[source][ip]', :source_mac => '[source][mac]',
      :source_vlan => '[network][vlan][id]', :source_hostname => '[source][hostname]',
      :source_oui => '[source][oui]', :netbox_url_base => 'http://example.test',
      :netbox_uri_suffix => '/api', :page_size => 100, :default_status => :active,
      :nb_headers => {}, :cache_size => 100, :cache_ttl => 30, :lookup_cache_size => 20,
      :site_lookup_types_hash => FakeCache.new, :identity_context_hash => FakeCache.new,
      :device_tag_autopopulated => { :slug => 'malcolm-autopopulated' },
      :device_tag_hostname_unknown => { :slug => 'hostname-unknown' },
      :device_tag_manufacturer_unknown => { :slug => 'manufacturer-unknown' }
    }.each { |key,value| instance_variable_set("@#{key}", value) }
  end
  def lookup_or_create_site(*); { :id => 1, :name => 'Test Site' }; end
  def lookup_prefixes(*); []; end
  def lookup_or_create_role(*); { :id => 1, :name => 'Test Role' }; end
  def lookup_or_create_manuf_and_dtype(*args)
    $test_nb.oui_inputs << args.first
    [{ :id => 1, :name => 'Test Type' }, { :id => 1, :name => 'Test Vendor', :vm => false }]
  end
  def mac_to_oui_lookup(*); 'Test Vendor'; end
end
class IdentityFilter::NetBoxConnLazy
  def self.new(*); $test_nb; end
end
FakeEvent = Struct.new(:fields) do
  def get(key); fields[key]; end
  def set(key,value); fields[key] = value; end
end
Response = Struct.new(:body, :status) do
  def success?; status >= 200 && status < 300; end
end
class FakeNetbox
  attr_accessor :ips, :macs, :prefixes, :fail_path, :devices, :interfaces
  attr_reader :writes, :oui_inputs
  def initialize
    @writes, @oui_inputs = [], []
    native = { :id => 10, :name => 'PC-EXAMPLE', :site => { :id => 1, :name => 'Test Site' },
               :url => 'http://example.test/api/dcim/devices/10/', :tags => [] }
    auto = { :id => 20, :name => 'pc-example.local', :site => { :id => 1, :name => 'Test Site' },
             :url => 'http://example.test/api/dcim/devices/20/', :tags => [{ :slug => 'malcolm-autopopulated' }] }
    @devices = { 10 => native, 20 => auto }
    @interfaces = { 101 => { :id => 101, :device => native, :vrf => nil },
                    201 => { :id => 201, :device => auto, :vrf => nil } }
    @ips = [{ :id => 401, :address => '10.10.0.7/32', :vrf => nil,
              :assigned_object_type => 'dcim.interface', :assigned_object_id => 201,
              :assigned_object => @interfaces[201] }]
    @macs = [{ :id => 301, :mac_address => '02:11:22:33:44:55',
               :assigned_object_type => 'dcim.interface', :assigned_object_id => 101 }]
    @prefixes = [{ :id => 1, :prefix => '10.10.0.0/24', :vrf => nil,
                   :scope_type => 'dcim.site', :scope_id => 1, :vlan => { :id => 1, :vid => 10 } }]
  end
  def initialized?; true; end
  def response(body,status=200); Response.new(Marshal.load(Marshal.dump(body)),status); end
  def get(path,query={})
    return response({},503) if path == @fail_path
    data = case path
    when 'ipam/ip-addresses/'
      @ips.select { |i| IPAddr.new(i[:address].split('/').first).to_s == query[:address] }
    when 'dcim/mac-addresses/'
      @macs.select { |m| m[:mac_address].upcase == query[:mac_address] }
    when 'ipam/prefixes/'; @prefixes
    when 'dcim/devices/'
      @devices.values.select { |d| d[:name].downcase.include?(query[:q].to_s.downcase) }
    when %r{\Adcim/devices/(\d+)/\z}; return response(@devices.fetch($1.to_i))
    when %r{\A(?:dcim|virtualization)/interfaces/(\d+)/\z}; return response(@interfaces.fetch($1.to_i))
    when 'ipam/vlans/1/'; return response({ :id => 1, :vid => 10, :group => { :id => 1 } })
    when 'ipam/vlan-groups/1/'; return response({ :scope_type => 'dcim.site', :scope_id => 1 })
    when 'dcim/locations/1/'; return response({ :site => { :id => 1 } })
    else; raise "unexpected GET #{path} #{query}"
    end
    response({ :results => data.slice(query.fetch(:offset,0),query.fetch(:limit,100)) || [] })
  end
  def post(path,text,*)
    data=JSON.parse(text,:symbolize_names => true)
    @writes << [:post,path,data]
    case path
    when 'dcim/devices/'
      data[:id] = 900
      data[:site] = { :id => data[:site], :name => 'Test Site' }
      data[:role] = { :id => data[:role], :name => 'Test Role' }
      data[:device_type] = { :id => data[:device_type], :name => 'Test Type',
                             :manufacturer => { :id => 1, :name => 'Test Vendor' } }
      data[:url] = 'http://example.test/api/dcim/devices/900/'
      @devices[900] = data
    when 'dcim/interfaces/'
      data[:id] = 901
      data[:device] = @devices.fetch(data[:device])
      @interfaces[901] = data
    when 'dcim/mac-addresses/'
      data[:id] = 902
      @macs << data
    when 'ipam/ip-addresses/'
      data[:id] = 903
      data[:assigned_object] = @interfaces.fetch(data[:assigned_object_id])
      @ips << data
    else; raise "unexpected POST #{path}"
    end
    response(data,201)
  end
  def patch(path,text,*)
    data=JSON.parse(text,:symbolize_names => true)
    @writes << [:patch,path,data]
    case path
    when %r{\A(?:dcim|virtualization)/interfaces/(\d+)/\z}; @interfaces.fetch($1.to_i).merge!(data)
    when %r{\Adcim/devices/(\d+)/\z}; @devices.fetch($1.to_i).merge!(data)
    else; raise "unexpected PATCH #{path}"
    end
    response(data.merge(:id => path.split('/')[-1].to_i))
  end
end

def event(mac='02:11:22:33:44:55',vlan=10,hostname=nil)
  FakeEvent.new({ '[source][ip]' => '10.10.0.7', '[source][mac]' => mac,
                  '[network][vlan][id]' => vlan, '[source][hostname]' => hostname })
end
def lookup(filter,event=event())
  filter.netbox_lookup(:event => event, :ip_key => '10.10.0.7', :site_id => 1).first
end
results={}
def check(results,name)
  $test_nb = FakeNetbox.new
  filter=IdentityFilter.new
  raise "failed: #{name}" unless yield(filter,$test_nb)
  results[name]=true
end
check(results,'native_mac_replaces_auto_enrichment_without_writes') do |f,nb|
  r=lookup(f)
  r[:id]==[10] && r[:identity_source]==['local_mac'] && r[:ip_assignment_conflict]==[true] && nb.writes.empty?
end
check(results,'native_mac_without_ip_assignment') do |f,nb|
  nb.ips=[]
  lookup(f)[:id]==[10] && nb.writes.empty?
end
check(results,'assigned_host_with_24_mask') do |f,nb|
  nb.ips.first[:address]='10.10.0.7/24'
  nb.ips.first[:assigned_object]=nb.interfaces[101]
  nb.ips.first[:assigned_object_id]=101
  lookup(f)[:id]==[10] && nb.writes.empty?
end
check(results,'unassigned_24_does_not_create_32') do |f,nb|
  nb.macs=[]
  nb.ips=[{ :id => 401, :address => '10.10.0.7/24', :assigned_object_id => nil }]
  r=lookup(f)
  r[:identity_status]==['unassigned_or_out_of_scope_ip_review'] && nb.writes.empty? && nb.ips.size==1
end
check(results,'duplicate_masks_flagged_without_writes') do |f,nb|
  nb.macs=[]
  nb.ips << { :id => 402, :address => '10.10.0.7/24' }
  lookup(f)[:ip_record_conflict]==[true] && nb.writes.empty?
end
check(results,'routed_vlan_does_not_assign_mac') do |f,nb|
  nb.macs=[]
  lookup(f,event('02:11:22:33:44:55',99))[:id]==[20] && nb.writes.empty?
end
check(results,'missing_vlan_does_not_assign_mac') do |f,nb|
  nb.macs=[]
  lookup(f,event('02:11:22:33:44:55',nil))[:id]==[20] && nb.writes.empty?
end
check(results,'multiple_vlans_do_not_assign_mac') do |f,nb|
  nb.macs=[]
  lookup(f,event('02:11:22:33:44:55',[10,20]))[:id]==[20] && nb.writes.empty?
end
check(results,'vrf_requires_context') do |f,nb|
  nb.ips.first[:vrf]={ :id => 2 }
  lookup(f)[:identity_status]==['vrf_context_required'] && nb.writes.empty?
end
check(results,'native_ip_mac_conflict_is_not_overwritten') do |f,nb|
  nb.devices[20][:tags]=[]
  lookup(f)[:identity_status]==['conflict_review'] && nb.writes.empty?
end
check(results,'duplicate_mac_objects_require_review') do |f,nb|
  nb.macs << nb.macs.first.merge(:id => 302)
  lookup(f)[:identity_status]==['conflict_review'] && nb.writes.empty?
end
check(results,'hostname_only_prevents_duplicate_without_assignment') do |f,nb|
  nb.ips=[]
  nb.macs=[]
  r=lookup(f,event(nil,nil,'PC-EXAMPLE.local'))
  r[:identity_status]==['hostname_review'] && !r.key?(:id) && nb.writes.empty?
end
check(results,'modern_mac_creation_and_repeat_are_idempotent') do |f,nb|
  nb.ips=[]; nb.macs=[]; nb.devices={}; nb.interfaces={}
  lookup(f)
  lookup(f)
  posts=nb.writes.select { |w| w[0]==:post }
  posts.map { |w| w[1] }.sort==['dcim/devices/','dcim/interfaces/','dcim/mac-addresses/','ipam/ip-addresses/'].sort &&
    !posts.find { |w| w[1]=='dcim/interfaces/' }[2].key?(:mac_address) &&
    nb.macs.first[:assigned_object_id]==901 && nb.interfaces[901][:primary_mac_address]==902 &&
    nb.ips.first[:address]=='10.10.0.7/32'
end
check(results,'backfill_only_auto_interface') do |f,nb|
  nb.macs=[]
  lookup(f)
  nb.macs.size==1 && nb.macs.first[:assigned_object_id]==201 && nb.interfaces[201][:primary_mac_address]==902
end
check(results,'imported_primary_mac_is_not_modified') do |f,nb|
  lookup(f)
  nb.interfaces[101][:primary_mac_address].nil? && nb.writes.empty?
end
check(results,'unassigned_existing_mac_is_not_claimed') do |f,nb|
  nb.macs.first[:assigned_object_id]=nil
  nb.ips=[]
  lookup(f)[:identity_status]==['existing_mac_review'] && nb.writes.empty?
end
check(results,'other_interface_mac_is_not_moved') do |f,nb|
  f.ensure_interface_mac(nb.interfaces[201],'dcim.interface','02:11:22:33:44:55',nb)
  nb.writes.empty?
end
check(results,'existing_primary_is_preserved') do |f,nb|
  nb.macs=[]; nb.interfaces[201][:primary_mac_address]={ :id => 999 }
  f.ensure_interface_mac(nb.interfaces[201],'dcim.interface','02:11:22:33:44:55',nb)
  nb.macs.size==1 && nb.writes.none? { |w| w[0]==:patch }
end
check(results,'vm_mac_assignment_uses_vm_interface_type') do |f,nb|
  nb.macs=[]
  f.ensure_interface_mac(nb.interfaces[201],'virtualization.vminterface','02:11:22:33:44:55',nb)
  nb.macs.first[:assigned_object_type]=='virtualization.vminterface' &&
    nb.writes.last[1]=='virtualization/interfaces/201/'
end
check(results,'api_failure_does_not_create_inventory') do |f,nb|
  nb.fail_path='ipam/ip-addresses/'
  lookup(f).nil? && nb.writes.empty?
end
check(results,'pagination_checks_all_mac_objects') do |f,nb|
  f.instance_variable_set(:@page_size,1)
  nb.macs << nb.macs.first.merge(:id => 302)
  lookup(f)[:identity_status]==['conflict_review'] && nb.writes.empty?
end
check(results,'vlan_group_supplies_site_for_unscoped_prefix') do |f,nb|
  nb.prefixes.first[:scope_type]=nil; nb.prefixes.first.delete(:scope_id)
  lookup(f)[:id]==[10] && nb.writes.empty?
end
check(results,'location_scope_is_resolved') do |f,nb|
  nb.prefixes.first[:scope_type]='dcim.location'
  lookup(f)[:id]==[10] && nb.writes.empty?
end
check(results,'wrong_site_does_not_trust_mac') do |f,nb|
  nb.prefixes.first[:scope_id]=2
  lookup(f)[:id]==[20] && nb.writes.empty?
end
check(results,'ambiguous_prefix_does_not_trust_mac') do |f,nb|
  nb.prefixes << nb.prefixes.first.merge(:id => 2)
  lookup(f)[:id]==[20] && nb.writes.empty?
end
check(results,'invalid_multicast_and_multiple_macs_are_rejected') do |f,nb|
  [nil,[],['02:11:22:33:44:55','02:11:22:33:44:66'],'01:11:22:33:44:55','00:00:00:00:00:00','not-a-mac'].all? { |m| f.identity_mac(m).nil? }
end
check(results,'filter_cache_separates_local_and_routed_observations') do |f,nb|
  local=event; routed=event('02:11:22:33:44:55',99)
  f.filter(local); f.filter(routed)
  local.get('[source][device]')[:id]==[10] && routed.get('[source][device]')[:id]==[20] && nb.writes.empty?
end
check(results,'concurrent_first_observations_create_one_host') do |f,nb|
  nb.ips=[]; nb.macs=[]; nb.devices={}; nb.interfaces={}
  filters=[f,IdentityFilter.new]
  threads=filters.map { |filter| Thread.new { lookup(filter) } }
  threads.each(&:value)
  nb.writes.count { |w| w[0]==:post && w[1]=='dcim/devices/' }==1 && nb.ips.size==1 && nb.macs.size==1
end
check(results,'filter_cache_preserves_lookup_tuple_after_update') do |f,nb|
  nb.macs=[]
  nb.devices[20][:tags] << { :slug => 'hostname-unknown' }
  first=event(nil,nil,'NEW-PC'); second=event(nil,nil,'NEW-PC')
  f.filter(first); f.filter(second)
  first.get('[source][device]')[:name]==['NEW-PC'] && second.get('[source][device]')[:name]==['NEW-PC'] &&
    nb.writes.count { |w| w[0]==:patch && w[1]=='dcim/devices/20/' }==1
end
puts JSON.generate(results)
