module Best_Guess;

# given an input map file with the following format:
# proto	dport	sport	name	category
# (see https://docs.zeek.org/en/master/frameworks/input.html#reading-data-into-tables
# for details on how the table is loaded),
# load up the table on zeek_init and for each connection_state_remove
# make a "best guess" of protocols based on proto+dport+sport.
# Best guesses are written to bestguess according to Best_Guess::Info

# Table key is transport protocol + destination port + source port
# Zeek will segfault if there is an unset value ('-') in the key,
# so use unknown_transport and 0 for protocol and ports, respectively,
# if they are not defined in the lookup.
type Best_Guess_Key: record {
  proto: transport_proto &optional;
  dport: count &optional;
  sport: count &optional;
};


# Other table values include name, category.
type Best_Guess_Value: record {
  name: string &optional;
  category: string &optional;
};

export {
  redef enum Log::ID += { BEST_GUESS_LOG };

  #############################################################################
  # This is the format of bestguess.log

  type Info: record {

    # Timestamp for when the event happened.
    ts: time &log;

    # Unique ID for the connection.
    uid: string &log;

    # The connection's 4-tuple of endpoint addresses/ports.
    id: conn_id &log;

    # transport protocol
    proto: transport_proto &log &optional;

    # protocol guess values for log
    name: string &log &optional;
    category: string &log &optional;

    # originating structure containing guess info
    guess_info: Best_Guess_Value &optional;
  };

  # Event that can be handled to access the record as it is sent on to the logging framework.
  global log_best_guess: event(rec: Best_Guess::Info);
}

# lookup table of Best_Guess_Key -> Best_Guess_Value to be loaded in zeek_init
global proto_guesses: table[transport_proto, count, count] of Best_Guess_Value = table();
# filespec containing best guess mappings
global guest_map_filespec : string = @DIR + "/guess_ics_map.txt";

#############################################################################
event zeek_init() &priority=5 {
  # populate the lookup table from guest_map_filespec and then clean up the intermediate source
  Input::add_table([$source=guest_map_filespec, $name="guess_ics_map",
                    $idx=Best_Guess_Key, $val=Best_Guess_Value,
                    $destination=proto_guesses, $want_record=T]);
  Input::remove("guess_ics_map");

  # initialize bestguess.log
  Log::create_stream(Best_Guess::BEST_GUESS_LOG, [$columns=Best_Guess::Info, $ev=log_best_guess, $path="bestguess"]);
}

#############################################################################
event connection_state_remove(c: connection) {
  local p = get_port_transport_proto(c$id$resp_p);
  local dp = port_to_count(c$id$resp_p);
  local sp = port_to_count(c$id$orig_p);
  local guess = Best_Guess_Value($name="");
  local category: string = "";

  # 1. only check connections for which we don't already know "service"
  # 2. skip ICMP, since dp and sp don't mean the same thing for ICMP
  if (((!c?$service) || (|c$service| == 0)) && (p != icmp)) {

    # Look up permutations of transport protocol + destination port + source port
    # from more-specific to less-specific.
    if ([p, dp, sp] in proto_guesses)
      guess = proto_guesses[p, dp, sp];
    else if ([p, dp, 0] in proto_guesses)
      guess = proto_guesses[p, dp, 0];
    else if ([p, 0, sp] in proto_guesses)
      guess = proto_guesses[p, 0, sp];
    else if ([unknown_transport, dp, sp] in proto_guesses)
      guess = proto_guesses[unknown_transport, dp, sp];
    else if ([unknown_transport, dp, 0] in proto_guesses)
      guess = proto_guesses[unknown_transport, dp, 0];
    else if ([unknown_transport, 0, sp] in proto_guesses)
      guess = proto_guesses[unknown_transport, 0, sp];

    # if a best guess was made based on protocol and ports, log it
    if ((guess?$name) && (guess$name != "")) {

      # as category may be undefined, check before accessing
      if (guess?$category)
        category = guess$category;

      # log entry into bestguess.log
      local info = Best_Guess::Info($ts=network_time(),
                                    $uid=c$uid,
                                    $id=c$id,
                                    $proto=p,
                                    $name=guess$name,
                                    $category=category,
                                    $guess_info=guess);
      Log::write(Best_Guess::BEST_GUESS_LOG, info);

    } # found guess
  } # if (p != icmp)
} # connection_state_remove