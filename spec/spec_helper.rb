# frozen_string_literal: true

# Set variable
host_os = RbConfig::CONFIG['host_os']
extension = case host_os
            when /darwin|mac os/
              '.dylib'
            when /linux/
              '.so'
            else
              raise "#{host_os} is an unsupported os."
            end
lib_path = File.expand_path("../depends/secp256k1-zkp/.libs/libsecp256k1#{extension}", __dir__)
ENV['LIBSECP256K1-ZKP'] = lib_path

require 'secp256k1zkp'

RSpec.configure do |config|
  # Enable flags like --only-failures and --next-failure
  config.example_status_persistence_file_path = '.rspec_status'

  # Disable RSpec exposing methods globally on `Module` and `main`
  config.disable_monkey_patching!

  config.expect_with :rspec do |c|
    c.syntax = :expect
  end

  config.before(:all) do

  end
end

# Convert hex to binary.
def hex!(hex)
  [hex].pack('H*')
end

def context_none
  Secp256k1zkp::Context.new(caps: Secp256k1zkp::SECP256K1_CONTEXT_NONE)
end

def context_verify
  Secp256k1zkp::Context.new(caps: Secp256k1zkp::SECP256K1_CONTEXT_VERIFY)
end

def context_sign
  Secp256k1zkp::Context.new(caps: Secp256k1zkp::SECP256K1_CONTEXT_SIGN)
end
