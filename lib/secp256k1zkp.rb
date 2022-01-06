# frozen_string_literal: true

require 'ffi'
require 'securerandom'
require 'secp256k1zkp/version'
require 'secp256k1zkp/c'
require 'secp256k1zkp/context'
require 'secp256k1zkp/key'
require 'secp256k1zkp/ecdsa'

# Nimbleness's secp256k1-zkp binding.
# https://github.com/mimblewimble/secp256k1-zkp
module Secp256k1zkp

  class Error < StandardError; end
  class AssertError < Error; end
  class InvalidPublicKey < Error; end
  class InvalidPrivateKey < Error; end
  class InvalidSignature < Error; end

end
