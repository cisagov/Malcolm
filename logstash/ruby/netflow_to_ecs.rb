# Copyright (c) 2026 Battelle Energy Alliance, LLC. All rights reserved.
# Normalize standard v9 fields, keeping vendor-specific fields under [netflow].
require 'json'

def register(_params)
end

def filter(event)
  record = event.get('[netflow]')
  return [] unless record.is_a?(Hash)

  {
    'ipv4_src_addr' => '[source][ip]',
    'ipv4_dst_addr' => '[destination][ip]',
    'l4_src_port' => '[source][port]',
    'l4_dst_port' => '[destination][port]',
    'in_bytes' => '[network][bytes]',
    'in_pkts' => '[network][packets]'
  }.each do |source_key, ecs_field|
    value = record[source_key]
    event.set(ecs_field, value) unless value.nil?
  end

  protocol = record['protocol']
  unless protocol.nil?
    event.set('[network][transport]', {
      1 => 'icmp', 6 => 'tcp', 17 => 'udp', 58 => 'icmpv6'
    }.fetch(protocol.to_i, protocol.to_s))
  end

  event.set('[event][module]', 'netflow')
  event.set('[event][dataset]', 'netflow.v9')
  event.set('[event][kind]', 'event')
  event.set('[event][category]', ['network'])
  event.set('[event][type]', ['info'])
  # The beats pipeline fingerprints original + timestamp to avoid deduplicating
  # multiple flow records received at the same instant.
  event.set('[event][original]', JSON.generate(record))
  [event]
end
