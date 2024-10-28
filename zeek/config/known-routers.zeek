##! This script logs routers, devices that Zeek determines have
##! sent IPv4 packets with TTL 255 or IPv6 packets with HLIM 255,
##! and logs the address once per day (by default). It is modeled
##! pretty heavily after known-hosts.zeek

@load base/utils/directions-and-hosts
@load base/frameworks/cluster

module Known;

export {
   ## The known-routers logging stream identifier.
   redef enum Log::ID += { ROUTERS_LOG };

   ## A default logging policy hook for the stream.
   global log_policy_routers: Log::PolicyHook;

   ## The record type which contains the column fields of the known-routers log.
   type RouterInfo: record {
      ## The timestamp at which the router was detected.
      ts: time &log;
      ## The originating IPv4 or IPv6 address of the detected packet with the 255 TTL/HLIM value.
      orig_h: addr &log;
      ## The originating MAC address of the detected packet with the 255 TTL/HLIM value.
      orig_l2_addr: string &log &optional;
      ## When IPv4, the TTL value.
      ttl: count &log &optional;
      ## When IPv6, the HLIM value.
      hlim: count &log &optional;
   };

   ## Toggles between different implementations of this script.
   ## When true, use a Broker data store, else use a regular Zeek set
   ## with keys uniformly distributed over proxy nodes in cluster
   ## operation.
   const use_router_store = F &redef;

   ## The router hosts whose existence should be logged and tracked.
   ## See :zeek:type:`Host` for possible choices.
   option router_tracking = LOCAL_HOSTS;

   ## Holds the set of all known routers.  Keys in the store are addresses
   ## and their associated value will always be the "true" boolean.
   global router_store: Cluster::StoreInfo;

   ## The Broker topic name to use for :zeek:see:`Known::router_store`.
   const router_store_name = "zeek/known/routers" &redef;

   ## The expiry interval of new entries in :zeek:see:`Known::router_store`.
   ## This also changes the interval at which routers get logged.
   const router_store_expiry = 1day &redef;

   ## The timeout interval to use for operations against
   ## :zeek:see:`Known::router_store`.
   option router_store_timeout = 15sec;

   ## The set of all known addresses to store for preventing duplicate
   ## logging of addresses.  It can also be used from other scripts to
   ## inspect if an address has been seen in use.
   ## Maintain the list of known routers for 24 hours so that the existence
   ## of each individual address is logged each day.
   ##
   ## In cluster operation, this set is distributed uniformly across
   ## proxy nodes.
   global routers: set[addr] &create_expire=1day &redef;

   ## An event that can be handled to access the :zeek:type:`Known::RouterInfo`
   ## record as it is sent on to the logging framework.
   global log_known_routers: event(rec: RouterInfo);
}

event zeek_init() {
   if ( ! Known::use_router_store )
      return;
   Known::router_store = Cluster::create_store(Known::router_store_name);
}

event Known::router_found(info: RouterInfo) {
   if ( ! Known::use_router_store )
      return;

   when [info] ( local r = Broker::put_unique(Known::router_store$store,
                                              info$orig_h,
                                              T,
                                              Known::router_store_expiry) ) {
      if ( r$status == Broker::SUCCESS ) {
         if ( r$result as bool )
            Log::write(Known::ROUTERS_LOG, info);
      } else
         Reporter::error(fmt("%s: data store put_unique failure",
                             Known::router_store_name));
   }

   timeout Known::router_store_timeout {
      # Can't really tell if master store ended up inserting a key.
      Log::write(Known::ROUTERS_LOG, info);
   }
}

event known_router_add(info: RouterInfo) {
   if ( use_router_store )
      return;

   if ( info$orig_h in Known::routers )
      return;

   add Known::routers[info$orig_h];

   @if ( ! Cluster::is_enabled() || Cluster::local_node_type() == Cluster::PROXY )
      Log::write(Known::ROUTERS_LOG, info);
   @endif
}

event Cluster::node_up(name: string, id: string) {
   if ( use_router_store )
      return;

   if ( Cluster::local_node_type() != Cluster::WORKER )
      return;

   # Drop local suppression cache on workers to force HRW key repartitioning.
   clear_table(Known::routers);
}

event Cluster::node_down(name: string, id: string) {
   if ( use_router_store )
      return;

   if ( Cluster::local_node_type() != Cluster::WORKER )
      return;

   # Drop local suppression cache on workers to force HRW key repartitioning.
   clear_table(Known::routers);
}

event Known::router_found(info: RouterInfo) {
   if ( use_router_store )
      return;

   if ( info$orig_h in Known::routers )
      return;

   Cluster::publish_hrw(Cluster::proxy_pool, info$orig_h, known_router_add, info);
   event known_router_add(info);
}

event zeek_init() &priority=5 {
   Log::create_stream(Known::ROUTERS_LOG, [$columns=RouterInfo,
                                           $ev=log_known_routers,
                                           $path="known_routers",
                                           $policy=log_policy_routers]);
}

event new_connection(c: connection) &priority=5 {
   local p: raw_pkt_hdr = get_current_packet_header();

   if ( ( ( p?$ip && ( p$ip$ttl == 255 ) ) || ( p?$ip6 && ( p$ip6$hlim == 255 ) ) ) && ( addr_matches_host(c$id$orig_h, router_tracking) ) ) {

      local ttl : count = 0;
      local hlim : count = 0;
      local mac : string = "";
      if ( p?$ip ) ttl = p$ip$ttl;
         else if ( p?$ip6 ) hlim = p$ip6$hlim;
      if ( c?$orig && c$orig?$l2_addr ) mac = c$orig$l2_addr;

      event Known::router_found([$ts=network_time(),
                                 $orig_h=c$id$orig_h,
                                 $ttl=ttl,
                                 $hlim=hlim,
                                 $orig_l2_addr=mac]);

   }
}