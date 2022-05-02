# frozen_string_literal: true

require 'ffi'
require 'securerandom'
require 'tapyrus_zkp/version'
require 'tapyrus_zkp/c'
require 'tapyrus_zkp/context'
require 'tapyrus_zkp/key'
require 'tapyrus_zkp/ecdsa'
require 'tapyrus_zkp/ecdh'
require 'tapyrus_zkp/agg_sig'
require 'tapyrus_zkp/generator'
require 'tapyrus_zkp/pedersen'

# Tapyrus secp256k1-zkp binding.
# https://github.com/chaintope/secp256k1
module TapyrusZkp

  class Error < StandardError; end
  class AssertError < Error; end
  class InvalidPublicKey < Error; end
  class InvalidPrivateKey < Error; end
  class InvalidSignature < Error; end
  class PartialSigFailure < Error; end
  # A Secp256k1zkp was used for an operation, but it was not created to support this.
  class IncapableContext < Error; end
  class InvalidCommit < Error; end
  class InvalidFactor < Error; end
  class IncorrectCommitSum < Error; end

  ZERO_256 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0].freeze

  class ::Integer
    def to_even_hex(bytesize = nil)
      hex = to_s(16)
      padding = bytesize ? bytesize * 2 : (hex.length / 2.0).ceil * 2
      hex.rjust(padding, '0')
    end
  end
end
