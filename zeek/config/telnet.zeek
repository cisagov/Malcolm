global telnet_ports: set[port] = { 23/tcp } &redef;

event zeek_init()
{
  Analyzer::register_for_ports(Analyzer::ANALYZER_TELNET, telnet_ports);
  Analyzer::register_for_ports(Analyzer::ANALYZER_RSH, telnet_ports);
  Analyzer::register_for_ports(Analyzer::ANALYZER_RLOGIN, telnet_ports);
}

event login_confused(c: connection, msg: string, line: string)
{
  # print "login_confused", msg, line;
  if (|c$service| == 0) add c$service["telnet"];
}

event login_failure(c: connection, user: string, client_user: string, password: string, line: string)
{
  # print "login_failure", user, client_user, password, line;
  if (|c$service| == 0) add c$service["telnet"];
}

event login_prompt(c: connection, prompt: string)
{
  # print "login_prompt", prompt;
  if (|c$service| == 0) add c$service["telnet"];
}

event login_success(c: connection, user: string, client_user: string, password: string, line: string)
{
  # print "login_success", user, client_user, password, line;
  if (|c$service| == 0) add c$service["telnet"];
}

# for file in /host/telnet/*; do cd /tmp; mkdir -p /host/logs/"$(basename "$file")"; /bin/rm -f /host/logs/"$(basename "$file")"/*; cd /host/logs/"$(basename "$file")"; zeek -r "$file" local /host/telnet.zeek > debug_output.txt; cd /tmp; done
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
