# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.

# Read-only NetBox lookup for non-network events identified by host.name.
# The Logstash Ruby filter interface calls register once and filter for each event.
require 'faraday'
require 'json'
require 'thread'

def register(params)
  @enabled = hostname_enrich_enabled?(params['enabled']) &&
             hostname_enrich_enabled?(params['netbox_enabled'])

  @source = params.fetch('source', '[host][name]')
  @target = params.fetch('target', '[host][netbox]')
  @site_field = params.fetch('site_field', '[@metadata][nbsiteid]')
  @default_site = params.fetch('default_site', ENV.fetch('NETBOX_DEFAULT_SITE', 'Malcolm')).to_s.strip

  @token = params['token'].to_s.strip
  if @token.empty?
    @token = [ENV['NETBOX_TOKEN'], ENV['SUPERUSER_API_TOKEN']]
             .map { |value| value.to_s.strip }
             .find { |value| !value.empty? }.to_s
  end

  @enabled &&= !@token.empty?
  @ttl_seconds = hostname_enrich_positive_setting('NETBOX_CACHE_TTL', 300, 3600)
  @max_cache_size = hostname_enrich_positive_setting('NETBOX_CACHE_SIZE', 10_000, 100_000)
  @cache = {}
  @cache_mutex = Mutex.new

  return unless @enabled

  url = params['netbox_url'].to_s.strip
  url = ENV.fetch('NETBOX_URL', '').to_s.strip if url.empty?
  url = 'http://netbox:8080/netbox' if url.empty?
  url = url.sub(%r{/*$}, '')
  url += '/api' unless url.end_with?('/api')
  @client = Faraday.new(url: "#{url}/")
end

def hostname_enrich_enabled?(value)
  %w[1 true t on enabled yes].include?(value.to_s.downcase)
end

def hostname_enrich_positive_setting(env, default, maximum)
  number = Integer(ENV.fetch(env, default).to_s, exception: false)
  number = default unless number && number.positive?
  [number, maximum].min
end

def hostname_enrich_cached(key)
  now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  cached = @cache_mutex.synchronize { @cache[key] }
  return cached[1] if cached && cached[0] > now

  value = yield
  @cache_mutex.synchronize do
    # Keep memory bounded for long-running Logstash processes.
    @cache.clear if @cache.size >= @max_cache_size
    @cache[key] = [now + @ttl_seconds, value]
  end
  value
end

def hostname_enrich_get(path, params)
  response = @client.get(path, params) do |request|
    request.headers['Authorization'] = "Token #{@token}"
    request.headers['Accept'] = 'application/json'
    request.options.timeout = 5
    request.options.open_timeout = 2
  end
  return nil unless response.status == 200

  payload = response.body.is_a?(Hash) ? response.body : JSON.parse(response.body.to_s)
  return nil unless payload.is_a?(Hash) && payload['results'].is_a?(Array)

  count = Integer(payload['count'], exception: false)
  return nil if count.nil? || count.negative? || payload['results'].length > count

  { count: count, results: payload['results'] }
rescue Faraday::Error, JSON::ParserError, TypeError, ArgumentError
  nil
end

def hostname_enrich_site_id(raw_site)
  site = raw_site.to_s.strip
  site = @default_site if site.empty?
  return nil if site.empty? || site == '0'
  return site.to_i if site.match?(/\A[1-9][0-9]*\z/)

  hostname_enrich_cached("site:#{site.downcase}") do
    response = hostname_enrich_get('dcim/sites/', name: site, limit: 2)
    next nil unless response && response[:count] == 1

    record = response[:results].first
    next nil unless record.is_a?(Hash) && record['name'].to_s.casecmp?(site)

    id = Integer(record['id'], exception: false)
    id if id && id.positive?
  end
end

def hostname_enrich_find(hostname, site_id)
  records = []
  [
    ['dcim/devices/', 'device'],
    ['virtualization/virtual-machines/', 'virtual_machine'],
  ].each do |path, kind|
    response = hostname_enrich_get(path, name: hostname, site_id: site_id, limit: 2)
    return nil unless response

    # Never infer identity when the API returns multiple candidates.
    return nil if response[:count] > 1

    response[:results].each do |record|
      next unless record.is_a?(Hash)
      next unless record['name'].to_s.casecmp?(hostname)
      next unless record['site'].is_a?(Hash)
      next unless record['site']['id'].to_i == site_id

      id = Integer(record['id'], exception: false)
      next unless id && id.positive?

      records << {
        'id' => id,
        'name' => record['name'],
        'site_id' => site_id,
        'kind' => kind,
      }
    end
  end

  records.size == 1 ? records.first : nil
end

def filter(event)
  return [event] unless @enabled
  return [event] unless event.get(@target).nil?

  # Network flow events already use IP-based NetBox enrichment.
  return [event] if event.get('[source][ip]') || event.get('[destination][ip]')

  hostname = event.get(@source)
  return [event] unless hostname.is_a?(String)

  hostname = hostname.strip.delete_suffix('.')
  # Reject non-hostname values, not arbitrary user-controlled API queries.
  return [event] unless hostname.match?(/\A[a-zA-Z0-9][a-zA-Z0-9._-]{0,252}\z/)

  raw_site = event.get(@site_field)
  return [event] if raw_site.to_s.strip == '0'
  site_id = hostname_enrich_site_id(raw_site)
  return [event] unless site_id

  lookup = hostname_enrich_cached("host:#{site_id}:#{hostname.downcase}") do
    hostname_enrich_find(hostname, site_id)
  end
  return [event] unless lookup

  event.set(@target, lookup)
  current_tags = Array(event.get('[tags]'))
  event.set('[tags]', current_tags | ['netbox'])
  [event]
rescue StandardError
  # A NetBox outage or malformed event must never stop Logstash ingestion.
  [event]
end
