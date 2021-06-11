module Best_Guess;

global zeek_disable_best_guess_ics = (getenv("ZEEK_DISABLE_BEST_GUESS_ICS") == "") ? F : T;

type Best_Guess_Key: record {
  proto: transport_proto &optional;
  sport: count &optional;
  dport: count &optional;
};

type Best_Guess_Value: record {
  name: string &optional;
};

global proto_guesses: table[Best_Guess_Key] of Best_Guess_Value = table();

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

    #
    guess: string &log &optional;

    #
    guess_info: Best_Guess_Value &optional;
  };

  # Event that can be handled to access the record as it is sent on
  # to the logging framework.
  global log_best_guess: event(rec: Best_Guess::Info);
}

#############################################################################
event zeek_init() &priority=5 {
  Input::add_table([$source="guess_ics_map.txt", $name="guess_ics_map",
                    $idx=Best_Guess_Key, $val=Best_Guess_Value, $destination=proto_guesses]);
  Input::remove("guess_ics_map");

  Log::create_stream(Best_Guess::BEST_GUESS_LOG, [$columns=Best_Guess::Info, $ev=log_best_guess, $path="bestguess"]);
}

#############################################################################
event connection_state_remove(c: connection) {
  if (!zeek_disable_best_guess_ics) {
    local p = get_port_transport_proto(c$id$resp_p);
    local sp = port_to_count(c$id$orig_p);
    local dp = port_to_count(c$id$resp_p);
    local guess = Best_Guess_Value($name="");

    # Check for the different permutations of proto/src_port/dst_port. Might be
    # worthwhile to check for most specific match first if its possible there are
    # multiple matches.
    if (Best_Guess_Key($proto=p,$sport=sp,$dport=dp) in proto_guesses)
      guess = proto_guesses[Best_Guess_Key($proto=p,$sport=sp,$dport=dp)];
    else if (Best_Guess_Key($proto=p,$dport=dp) in proto_guesses)
      guess = proto_guesses[Best_Guess_Key($proto=p,$dport=dp)];

    if (guess$name != "") {
      local info = Best_Guess::Info($ts=network_time(),
                                    $uid=c$uid,
                                    $id=c$id,
                                    $proto=p,
                                    $guess=guess$name,
                                    $guess_info=guess);
      Log::write(Best_Guess::BEST_GUESS_LOG, info);
    }
  }
}