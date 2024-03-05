module Login;

# log telnet, rlogin, and rsh events to login.log

export {

  redef enum Log::ID += {
    ## The logging stream identifier
    Log_LOGIN
  };

  type Info : record {
    ## Time the event occurred
    ts              : time &log;
    ## Unique ID for the connection
    uid             : string &log;
    ## The connection's 4-tuple of endpoint addresses/port
    id              : conn_id &log;

    ## proto (telnet, rlogin, or rsh)
    proto           : string &log &optional;
    ## login_success event was seen (successful login)
    success         : bool &log &default = F;
    ## login_confused event was seen (successful login)
    confused        : bool &log &default = F;
    ## username given for login attempt
    user            : string &log &optional;
    ## client_user given for login attempt (empty for telnet, set for rlogin)
    client_user     : string &log &optional;
    ## password given for login attempt
    password        : string &log &optional;

    ## whether or not a line has been written to login.log
    logged          : bool &default = F;
  };

  ## Event that can be handled to access the :zeek:type:`Login::Info`
  ## record as it is sent on to the logging framework.
  global log_login : event(rec : Info);
}

# Add the state tracking information variable to the connection record
redef record connection += {
  login : Info &optional;
};

###############################################
# constants borrowed from the old Bro 1.5 login.bro required to make some of the telnet/rlogin/rsh events work correctly
# see https://github.com/zeek/zeek/blob/release/1.5/policy/login.bro#L178
#     https://github.com/reservoirlabs/brorefguide/blob/master/analysis.texi#L3850

const skip_authentication: set[string] = { "WELCOME TO THE BERKELEY PUBLIC LIBRARY", } &redef;

const direct_login_prompts: set[string] = { "TERMINAL?", } &redef;

const login_prompts: set[string] = {
  "Login:",
  "login:",
  "Name:",
  "Username:",
  "User:",
  "Member Name",
  "User Access Verification",
  "Cisco Systems Console",
} &redef;

const login_non_failure_msgs: set[string] = {
  "Failures",
  "failures", # probably is "<n> failures since last login"
  "failure since last successful login",
  "failures since last successful login",
} &redef;

const login_failure_msgs: set[string] = {
  "invalid",
  "Invalid",
  "incorrect",
  "Incorrect",
  "failure",
  "Failure",
  # "Unable to authenticate",
  # "unable to authenticate",
  "User authorization failure",
  "Login failed",
  "INVALID",
  "Sorry.",
  "Sorry,",
} &redef;

const router_prompts: set[string] = {} &redef;

const login_success_msgs: set[string] = {
  "Last login",
  "Last successful login",
  "Last   successful login",
  "checking for disk quotas",
  "unsuccessful login attempts",
  "failure since last successful login",
  "failures since last successful login",
} &redef;

const login_timeouts: set[string] = {
  "timeout",
  "timed out",
  "Timeout",
  "Timed out",
  "Error reading command input",  # VMS
} &redef;
# end borrowed constants from Bro 1.5 login.bro
###############################################

# telnet, rlogin, rsh
const telnet_port = 23/tcp;
const telnet_ports = { telnet_port };
const rlogin_port = 513/tcp;
const rlogin_ports = { rlogin_port };
const rsh_port = 514/tcp;
const rsh_ports = { rsh_port };
redef likely_server_ports += { telnet_ports, rlogin_ports, rsh_ports };

# set_login_session - if has not yet been registered in the connection, instantiate
# the Info record and assign in c$login
function set_login_session(c : connection) {
  if ( ! c?$login ) {
    local s : Info = [$ts = network_time(), $uid = c$uid, $id = c$id];
    switch c$id$resp_p {
      case telnet_port:
        s$proto = "telnet";
        add c$service["telnet"];
        break;
      case rlogin_port:
        s$proto = "rlogin";
        add c$service["rlogin"];
        break;
      case rsh_port:
        s$proto = "rsh";
        add c$service["rsh"];
        break;
    }
    c$login = s;
  }
}

# login_message - log to login.log
function login_message(s : Info) {

  # strip some values that can happen in a "confused" state that aren't really valid values
  if (( s?$user ) && (( s$user == "" ) || ( s$user == "<none>" ) || ( s$user == "<timeout>" )))
    delete s$user;
  if (( s?$client_user ) && (( s$client_user == "" ) || ( s$client_user == "<none>" ) || ( s$client_user == "<timeout>" )))
    delete s$client_user;
  if (( s?$password ) && (( s$password == "" ) || ( s$password == "<none>" ) || ( s$password == "<timeout>" )))
    delete s$password;
  if (( s?$proto ) && ( s$proto == "" ))
    delete s$proto;

  s$ts = network_time();
  Log::write(Login::Log_LOGIN, s);
  s$logged = T;
}

# create log stream for login.log and register telnet, rlogin, and rsh analyzers
event zeek_init() &priority = 5 {
  Log::create_stream(Login::Log_LOGIN, [$columns = Info, $ev = log_login, $path = "login"]);
  Analyzer::register_for_ports(Analyzer::ANALYZER_TELNET, telnet_ports);
  Analyzer::register_for_ports(Analyzer::ANALYZER_RLOGIN, rlogin_ports);
  Analyzer::register_for_ports(Analyzer::ANALYZER_RSH, rsh_ports);
}

# login_confused - Generated when tracking of Telnet/Rlogin authentication failed
# https://docs.zeek.org/en/current/scripts/base/bif/plugins/Zeek_Login.events.bif.zeek.html#id-login_confused
event login_confused(c : connection, msg : string, line : string) &priority = 5 {
  # print "login_confused", msg, line;

  set_login_session(c);

  c$login$confused = T;
}

# login_failure - Generated when tracking of Telnet/Rlogin authentication failed
# https://docs.zeek.org/en/current/scripts/base/bif/plugins/Zeek_Login.events.bif.zeek.html#id-login_failure
event login_failure(c : connection, user : string, client_user : string, password : string, line : string) &priority = 5 {
  # print "login_failure", user, client_user, password, line;

  set_login_session(c);

  if ((!c$login?$user) || (c$login$user == ""))
    c$login$user = user;
  if ((!c$login?$client_user) || (c$login$client_user == ""))
    c$login$client_user = client_user;
  if ((!c$login?$password) || (c$login$password == ""))
    c$login$password = password;

  login_message(c$login);
}

# login_success - Generated for successful Telnet/Rlogin logins
# https://docs.zeek.org/en/current/scripts/base/bif/plugins/Zeek_Login.events.bif.zeek.html#id-login_success
event login_success(c : connection, user : string, client_user : string, password : string, line : string) &priority = 5 {
  # print "login_success", user, client_user, password, line;

  set_login_session(c);

  c$login$success = T;
  c$login$user = user;
  c$login$client_user = client_user;

  # it appears for a successful login with rsh where client_user was checked, what we're getting in
  # the "password" field is actually not the password, but the first line of data
  if ((c$login$proto != "rsh") || (c$login$client_user == ""))
    c$login$password = password;

  login_message(c$login);
}

event connection_state_remove(c : connection) &priority = -5 {
  if (c?$login) {

    if ( c$login$logged == F) {
      login_message(c$login);
    }

    delete c$login;
  }
}

# for testing:
# for file in /host/telnet/*; do cd /tmp; mkdir -p /host/logs/"$(basename "$file")"; /bin/rm -f /host/logs/"$(basename "$file")"/*; cd /host/logs/"$(basename "$file")"; zeek -r "$file" local > debug_output.txt; cd /tmp; done

# event activating_encryption(c: connection) { print "activating_encryption"; }
# event authentication_accepted(name: string, c: connection) { print "authentication_accepted", name; }
# event authentication_rejected(name: string, c: connection) { print "authentication_rejected", name; }
# event authentication_skipped(c: connection) { print "authentication_skipped"; }
# event bad_option(c: connection) { print "bad_option"; }
# event bad_option_termination(c: connection) { print "bad_option_termination"; }
# event inconsistent_option(c: connection) { print "inconsistent_option"; }
# event login_confused_text(c: connection, line: string) { print "login_confused_text", line; }
# event login_display(c: connection, display: string) { print "login_display", display; }
# event login_input_line(c: connection, line: string) { print "login_input_line", line; }
# event login_output_line(c: connection, line: string) { print "login_output_line", line; }
# event login_terminal(c: connection, terminal: string) { print "login_terminal", terminal; }
# event rsh_reply(c: connection, client_user: string, server_user: string, line: string) { print "rsh_reply", client_user, server_user, line; }
# event rsh_request(c: connection, client_user: string, server_user: string, line: string; new_session: bool) { print "rsh_request", client_user, server_user, line, new_session; }

