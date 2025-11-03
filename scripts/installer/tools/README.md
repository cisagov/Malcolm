Installer developer tools

Purpose: small, developer‑facing helpers that provide context during development and reviews. These are not used by the installer at runtime.

Tools
- dump_env_mapping.py
  - Prints a summary of the env mapping: env var to .env file, mapped ConfigItems, and reverse‑import roles.
  - Output fields
    - env_var, map_key, env_file: identity of the variable and owning .env
    - role: authoritative, derived, or mixed
      - authoritative: the env var is the source of truth for all of its mapped ConfigItems during reverse import
      - derived: the env var is never the source of truth for its mapped ConfigItems; it reflects other choices and should not override them on reverse import
      - mixed: the env var is authoritative for some mapped ConfigItems and derived for others
    - targets: compact list of mapped ConfigItems with roles per item, marked as (A) for authoritative or (D) for derived
    - reverse_noop: yes when the variable is intentionally ignored on reverse import to avoid conflicts
  - Interpreting “mixed”
    - Some env vars are computed from multiple ConfigItems and only drive part of their mapping on import.
    - Example: live capture selection for tcpdump and netsniff
      - PCAP_ENABLE_TCPDUMP maps to two settings: pcapTcpDump and pcapNetSniff
      - It is authoritative for pcapTcpDump (selecting tcpdump explicitly) and derived for pcapNetSniff (does not force netsniff on or off)
      - The tool will show role = mixed and targets listing pcapTcpDump(A) and pcapNetSniff(D)
  - Reverse no‑op variables
    - Variables that exist only to support forward generation or readability but should not set values on import are marked reverse_noop = yes
    - These are present in output for completeness; their values are ignored when ingesting environment files
  - Contributor note
    - When adding new env mappings, mark per‑item roles (authoritative or derived) on the EnvVariable and verify with the mapping tool (table output shows (A)/(D), JSON shows roles_by_item). Only mark reverse_noop when import must be skipped to avoid conflicts.
