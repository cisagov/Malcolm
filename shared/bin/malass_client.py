#!/usr/bin/env python3

# Copyright (c) 2021 Battelle Energy Alliance, LLC.  All rights reserved.

"""This script (malass_client.py) simulates the Malass 'file upload' HTML web form.
   The 'file upload' HTML form is used to 'upload a file', and several HTML form fields,
   to the Malass web server. (for scanning)

   Author:  Brett Rasmussen
   Date :   Mar 20, 2013
   Revised: Mar  8, 2019
   Revised: May  2, 2019 (Seth Grover)
"""

import requests
import sys

################################################################################
################################################################################
def parse_transaction_id(http_response_page):
  """ Parse the Malass transaction_id value from the passed in 'http_response_page'.

    http_response_page: (in) Web page returned by the Malass web site, in response
                             to a file upload operation.
    Return ok        (Boolean);
           error_msg (Error description on error);
           trans_id (The malass transaction_ID number.);
  """
  lpzProc = sys._getframe().f_code.co_name

  # A "Server Transaction ID #:" field might look like the following:
  #
  #    <td>Server Transaction ID #:</td><td><input name="trans_id" type="text" value="663"></td>
  #

  target_str_1 = "<td>Server Transaction ID #:"
  start_idx = http_response_page.find(target_str_1)
  pattern_found = (start_idx != -1)
  if (not pattern_found):
    return (False, f"{lpzProc}: Error: Could not find (1st) target_str={target_str_1}", "")

  target_str_2 = "value="
  start_idx_2 = http_response_page.find(target_str_2, start_idx)
  pattern_found = (start_idx_2 != -1)
  if (not pattern_found):
    return (False, f"{lpzProc}: Error: Could not find (2nd) target_str={target_str_2}", "")

  target_str_3 = '"'
  start_idx_3 = http_response_page.find(target_str_3, start_idx_2)
  pattern_found = (start_idx_3 != -1)
  if (not pattern_found):
    return (False, f"{lpzProc}: Error: Could not find (3rd) target_str={target_str_3}", "")

  trans_id_start_idx = start_idx_3 + 1
  target_str_4 = '"'
  start_idx_4 = http_response_page.find(target_str_4, trans_id_start_idx)
  pattern_found = (start_idx_4 != -1)
  if (not pattern_found):
    return (False, f"{lpzProc}: Error: Could not find (4th) target_str={target_str_4}", "")

  trans_id = http_response_page[trans_id_start_idx:start_idx_4]
  return (True, "", trans_id)

################################################################################
def post_multipart(url, fields={}, files={}):
  """
  Post fields and files to a host as HTTP MIME multipart/form-data.
    url    - The URL for the POST request
    fields - a dictionary of form fields, eg.: {'Upload_Button' : 'Upload File'},
    files  - a dictionary of files, eg.: {'file_1' : open('foobar.bin', 'rb')}

  Return the
    http response code;
    http response msg;
    http response page headers;
    http  server's response page.
  """
  lpzProc = sys._getframe().f_code.co_name

  parts = dict()
  parts.update(fields)
  parts.update(files)

  response = requests.post(url, files=parts)

  return (response.status_code, requests.status_codes._codes[response.status_code][0], response.headers, response.text)

################################################################################
def upload_file_to_malass(upload_file_path,  web_server_ip="127.0.0.1",  web_server_port="80"):
  """ Upload a file to the Malass web server, so that it may be scanned by
      the Malass application server.

      upload_file_path - (in) Full path of (local) file to upload to the Malass web site
                              (e.g. /tmp/my_image.jpeg )
      web_server_ip - (in) IP address of Malass web server.  Defaults to 127.0.0.1
                           (i.e. localhost)
      web_server_port  - (in) Web server port.  Defaults to port 80

    Returns: ok (Boolean);
             transaction_id (File upload transaction #);
             http_response_page/error_msg (Returned error page OR an Error description msg)
  """
  lpzProc = sys._getframe().f_code.co_name

  with open(upload_file_path, "rb") as upload_file_handle:
    error_code, error_msg1, headers, resp_str = post_multipart(url=f"http://{web_server_ip}:{web_server_port}/cgi-bin/file_upload.py",
                                                               fields={'Upload_Button' : 'Upload File'},
                                                               files={'file_1' : upload_file_handle})

  null_trans_id     = ""
  trans_id          = ""
  http_response_page = f"http response code={error_code}\nhttp_response_msg={error_msg1}\nhttp_headers=\n{headers}\nhttp_response_page=\n{resp_str}\n"

  if (error_code == 200):
    # Successful HTTP 'POST' operation:
    # Parse the 'transaction ID' from the http response:
    ok, error_msg, trans_id = parse_transaction_id(http_response_page)

    if (not ok):
      not_ok= False
      return (not_ok, null_trans_id, (f"{http_response_page}\n[Error parsing 'transaction ID' value.]"))

  else:
    not_ok= False
    return (not_ok, null_trans_id, (f"{http_response_page}\n[Error: Unexpected HTTP reponse code={error_code}.]"))

  return (True, trans_id, http_response_page)


################################################################################
def query_av_summary_rpt(transaction_id,              uploaded_file_name="",
                         web_server_ip="127.0.0.1",   web_server_port="80"):

  """ Query the 'AV summary report', for the specified
        'server transaction_id' OR
        'uploaded_file_name'
      value.

      (If a transaction_id is supplied, then the 'uploaded_file_name' field
      should be left blank.)

      (Note: you may also specify 'part of a filename' in the uploaded_file_name field.
      The most recently submitted, (matching) uploaded file transaction, will be
      returned.)

      Note: This routine connects to the Malass web server (rather than the
        Malass transaction server.)


      transaction_id     - (in) A Malass server transaction ID number. (or an
                                empty string)

      uploaded_file_name - (in) The 'base' name of a recently uploaded file.
                                (You may also submit part of a filename in this
                                parameter.) (Or, an empty string.)

      web_server_ip -     (in)  Malass web server IP address.  Defaults to
                                127.0.0.1 (i.e. localhost)
      web_server_port  - (in) Web server port.  Defaults to port 80.

    Returns ok (Boolean);
            error_msg: (Error description string)
            @@ av_summary_rpt_str (Current contents of the av_summary_rpt.txt file, as a
                                single string)
   """
  lpzProc = sys._getframe().f_code.co_name

  error_code, error_msg1, headers, resp_str = post_multipart(url=f"http://{web_server_ip}:{web_server_port}/cgi-bin/query_av_summary_rpt.py",
                                                             fields={'trans_id' : transaction_id, 'uploaded_filename' : uploaded_file_name})

  #print "\nerror_code=%s\n"  %  error_code
  #print "\nerror_msg1=%s\n"  %  error_msg1
  #print "\nheaders=%s\n"     %  headers
  #print "\nresponse_str=%s"  %  resp_str

  new_av_summary_rpt_str = resp_str
  return (True, "",  new_av_summary_rpt_str)
