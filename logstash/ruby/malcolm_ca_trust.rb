require 'openssl'

##############################################################################################
# Certificate store for TLS connections made from Logstash Ruby filters (NetBox, OTKB).
#
# Faraday's net_http adapter goes through JRuby's Net::HTTP and jruby-openssl, which verify
# against an OpenSSL::X509::Store built from PEM default paths. jdk-cacerts-auto-import.sh
# covers the Java plugins through the JVM's cacerts, but that isn't guaranteed to reach this
# path. Rather than depend on where jruby-openssl's default paths point on a given base image,
# start from those defaults and add every certificate found under PUSER_CA_TRUST (the
# ./nginx/ca-trust bind mount) explicitly.
#
# One store is built per Logstash process, on first use, and shared by every filter instance.
module MalcolmCaTrust
  CA_TRUST_DEFAULT = '/var/local/ca-trust'.freeze

  # same lower bound docker-uid-gid-setup.sh uses to skip placeholder files
  MIN_FILE_SIZE = 32

  @store = nil
  @mutex = Mutex.new

  class << self
    def cert_store
      @mutex.synchronize do
        @store ||= build(ENV['PUSER_CA_TRUST'].to_s.empty? ? CA_TRUST_DEFAULT : ENV['PUSER_CA_TRUST'])
      end
    end

    # Builds a new store from the default paths plus the file or directory at ca_trust.
    # Duplicates, non-certificate files and unreadable files are skipped, never raised, so
    # a stray file in the trust directory can't stop the pipeline from starting.
    def build(ca_trust, log: true)
      store = OpenSSL::X509::Store.new
      store.set_default_paths

      added = []
      ca_files(ca_trust).each do |f|
        begin
          store.add_file(f)
          added << File.basename(f)
        rescue StandardError
          # duplicate of a default root, not PEM, or unreadable
        end
      end

      if log && !added.empty?
        puts "malcolm_ca_trust: added #{added.length} CA file(s) from #{ca_trust}: #{added.join(', ')}"
      end
      store
    end

    private

    def ca_files(ca_trust)
      candidates =
        if File.directory?(ca_trust)
          # Dir.glob skips dot entries by default, which also skips Kubernetes configmap
          # internals (..data, ..2026_...); the top-level symlinks into them still resolve
          Dir.glob(File.join(ca_trust, '**', '*')).sort
        elsif File.file?(ca_trust)
          [ca_trust]
        else
          []
        end
      candidates.select { |f| File.file?(f) && File.size(f) >= MIN_FILE_SIZE }
    end
  end
end
