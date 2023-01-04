#!/usr/bin/env zeek

# Copyright (c) 2023 Battelle Energy Alliance, LLC.  All rights reserved.

@load ./extractor_params

global extractor_extract_mode = (getenv("ZEEK_EXTRACTOR_MODE") == "") ? extractor_extract_known : getenv("ZEEK_EXTRACTOR_MODE");
global extractor_max_size = (getenv("EXTRACTED_FILE_MAX_BYTES") == "") ? extractor_max_size_default : to_count(getenv("EXTRACTED_FILE_MAX_BYTES"));
redef FileExtract::prefix = (getenv("ZEEK_EXTRACTOR_PATH") == "") ? "./extract_files/" : getenv("ZEEK_EXTRACTOR_PATH");

event file_sniff(f: fa_file, meta: fa_metadata) {

      # extract all files OR
  if ((extractor_extract_mode == extractor_extract_all) ||
      # we don't know the mime type and we always want to extract unknowns OR
      ((! meta?$mime_type) && extractor_always_extract_unknown) ||
      # we only want to extract knowns and we know the mime type OR
      ((extractor_extract_mode == extractor_extract_known) && meta?$mime_type) ||
      # we only want to extract mime->extension mapped files, we know the mimetype, and the mime type is mapped
      ((extractor_extract_mode == extractor_extract_mapped) && meta?$mime_type && (meta$mime_type in extractor_mime_to_ext_map))) {

    local ext: string = "";
    if (! meta?$mime_type)
      ext = extractor_mime_to_ext_map["default"];
    else if (meta$mime_type in extractor_mime_to_ext_map)
      ext = extractor_mime_to_ext_map[meta$mime_type];
    else
      ext = split_string(meta$mime_type, /\//)[1];

    local ftime: time = 0.0;
    if (! f?$last_active)
      ftime = f$last_active;
    else
      ftime = network_time();

    local uid: string = "unknown";
    if (f?$conns)
      # todo this is a little hacky, figure out how to do this better
      for (cid in f$conns) {
        uid = f$conns[cid]$uid;
        break;
      }

    local fname = fmt("%s-%s-%s-%s.%s", f$source, f$id, uid, strftime("%Y%m%d%H%M%S", ftime), ext);
    Files::add_analyzer(f, Files::ANALYZER_EXTRACT, [$extract_filename=fname, $extract_limit=extractor_max_size]);
  }
}
