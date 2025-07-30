module iana_registry;

@load base/frameworks/logging/main
@load policy/protocols/conn/known-services

type IANA_Key: record {
  proto: transport_proto;
  dport: count;
};

type IANA_Value: record {
  name: string &optional;
  description: string &optional;
};

redef record Known::ServicesInfo += {
  iana_name: string &optional &log;
  iana_description: string &optional &log;
};

redef enum Log::ID += { IANA_SERVICE_LOG };

global disable_iana_lookup = (getenv("ZEEK_DISABLE_IANA_LOOKUP") == true_regex) ? T : F;
global iana_lookup: table[transport_proto, count] of IANA_Value = table();
global iana_lookup_ready = F;
global iana_map_file: string = @DIR + "/iana_service_map.txt";

event zeek_init() {
  Input::add_table([
    $source=iana_map_file,
    $name="iana_map",
    $idx=IANA_Key,
    $val=IANA_Value,
    $destination=iana_lookup,
    $want_record=T
  ]);

  if (!disable_iana_lookup) {
    local f = Log::get_filter(Known::SERVICES_LOG, "default");
    f$writer = Log::WRITER_NONE;
    Log::add_filter(Known::SERVICES_LOG, f);
    Log::create_stream(IANA_SERVICE_LOG, [
      $columns=Known::ServicesInfo,
      $path="known_services_iana"
    ]);
  }
}

event Input::end_of_data(name: string, source: string) {
  if (name == "iana_map") {
    iana_lookup_ready = T;
  }
}

event Known::log_known_services(rec: Known::ServicesInfo) {
  if (!disable_iana_lookup) {
    local r = rec;

    if (iana_lookup_ready) {
      local proto = r$port_proto;
      local dport = port_to_count(r$port_num);

      if ([proto, dport] in iana_lookup) {
        local svc = iana_lookup[proto, dport];
        r$iana_name = svc$name;
        r$iana_description = svc$description;
      }
    }

    Log::write(IANA_SERVICE_LOG, r);
  }
}
