# Copyright (c) 2026 Battelle Energy Alliance, LLC. All rights reserved.
# Promote selected exported AWS VPC Flow Log fields into ECS, retaining the
# original record under miscbeat for provider-specific queries.

def register(_params)
end

def filter(event)
  return [event] unless event.get('[event][module]') == 'aws_vpcflow'

  fields = {
    '[miscbeat][srcaddr]' => '[source][ip]',
    '[miscbeat][dstaddr]' => '[destination][ip]',
    '[miscbeat][srcport]' => '[source][port]',
    '[miscbeat][dstport]' => '[destination][port]',
    '[miscbeat][bytes]' => '[network][bytes]',
    '[miscbeat][packets]' => '[network][packets]',
    '[miscbeat][account_id]' => '[cloud][account][id]',
    '[miscbeat][region]' => '[cloud][region]',
    '[miscbeat][action]' => '[event][action]',
    '[miscbeat][raw]' => '[event][original]'
  }
  fields.each do |from, to|
    value = event.get(from)
    event.set(to, value) unless value.nil?
  end

  protocol = event.get('[miscbeat][protocol]')
  unless protocol.nil?
    event.set('[network][transport]', {
      1 => 'icmp', 6 => 'tcp', 17 => 'udp', 58 => 'icmpv6'
    }.fetch(protocol.to_i, protocol.to_s))
  end

  event.set('[cloud][provider]', 'aws')
  event.set('[event][provider]', 'aws')
  event.set('[event][dataset]', 'aws.vpcflow')
  event.set('[event][kind]', 'event')
  event.set('[event][category]', ['network'])
  event.set('[event][type]', ['info'])
  [event]
end
