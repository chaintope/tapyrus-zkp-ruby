# frozen_string_literal: true

require 'ffi'
require 'securerandom'
require 'secp256k1zkp/version'
require 'secp256k1zkp/c'
require 'secp256k1zkp/context'
require 'secp256k1zkp/key'
require 'secp256k1zkp/ecdsa'
require 'secp256k1zkp/ecdh'
require 'secp256k1zkp/agg_sig'

# Nimbleness's secp256k1-zkp binding.
# https://github.com/mimblewimble/secp256k1-zkp
module Secp256k1zkp

  class Error < StandardError; end
  class AssertError < Error; end
  class InvalidPublicKey < Error; end
  class InvalidPrivateKey < Error; end
  class InvalidSignature < Error; end
  class PartialSigFailure < Error; end
  # A Secp256k1zkp was used for an operation, but it was not created to support this.
  class IncapableContext < Error; end

  ZERO_256 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0].freeze

  class ::Integer
    def to_even_hex(bytesize = nil)
      hex = to_s(16)
      padding = bytesize ? bytesize * 2 : (hex.length / 2.0).ceil * 2
      hex.rjust(padding, '0')
    end
  end
end
