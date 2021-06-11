module Best_Guess;

global zeek_disable_best_guess_ics = (getenv("ZEEK_DISABLE_BEST_GUESS_ICS") == "") ? F : T;

type Best_Guess_Key: record {
  proto: transport_proto &optional;
  dport: count &optional;
  sport: count &optional;
};

type Best_Guess_Value: record {
  name: string &optional;
  category: string &optional;
  role: string &optional;
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

    #
    name: string &log &optional;
    category: string &log &optional;
    role: string &log &optional;

    #
    guess_info: Best_Guess_Value &optional;
  };

  # Event that can be handled to access the record as it is sent on
  # to the logging framework.
  global log_best_guess: event(rec: Best_Guess::Info);
}

global proto_guesses: table[transport_proto, count, count] of Best_Guess_Value = table();

#############################################################################
event zeek_init() &priority=5 {

 Input::add_table([$source="guess_ics_map.txt", $name="guess_ics_map",
                   $idx=Best_Guess_Key, $val=Best_Guess_Value,
                   $destination=proto_guesses, $want_record=T]);
 Input::remove("guess_ics_map");

  Log::create_stream(Best_Guess::BEST_GUESS_LOG, [$columns=Best_Guess::Info, $ev=log_best_guess, $path="bestguess"]);
}

#############################################################################
event connection_state_remove(c: connection) {
  if (!zeek_disable_best_guess_ics) {
    local p = get_port_transport_proto(c$id$resp_p);
    local dp = port_to_count(c$id$resp_p);
    local sp = port_to_count(c$id$orig_p);
    local guess = Best_Guess_Value($name="");
    local category: string = "";
    local role: string = "";

    if ([p, dp, sp] in proto_guesses)
      guess = proto_guesses[p, dp, sp];
    else if ([p, dp, 0] in proto_guesses)
      guess = proto_guesses[p, dp, 0];
    else if ([p, 0, sp] in proto_guesses)
      guess = proto_guesses[p, 0, sp];
    else if ([unknown_transport, dp, sp] in proto_guesses)
      guess = proto_guesses[unknown_transport, dp, sp];
    # TODO is this overkill?
    #else if ([unknown_transport, dp, 0] in proto_guesses)
    #  guess = proto_guesses[unknown_transport, dp, 0];
    #else if ([unknown_transport, 0, sp] in proto_guesses)
    #  guess = proto_guesses[unknown_transport, 0, sp];

    if ((guess?$name) && (guess$name != "")) {

      if (guess?$category)
        category = guess$category;
      if (guess?$role)
        role = guess$role;

      local info = Best_Guess::Info($ts=network_time(),
                                    $uid=c$uid,
                                    $id=c$id,
                                    $proto=p,
                                    $name=guess$name,
                                    $category=category,
                                    $role=role,
                                    $guess_info=guess);
      Log::write(Best_Guess::BEST_GUESS_LOG, info);
    }
  }
}