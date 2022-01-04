# frozen_string_literal: true

require 'ffi'
require 'secp256k1zkp/version'
require 'secp256k1zkp/c'
require 'secp256k1zkp/context'
require 'secp256k1zkp/key'

# Nimbleness's secp256k1-zkp binding.
# https://github.com/mimblewimble/secp256k1-zkp
module Secp256k1zkp

  class Error < StandardError; end
  class InvalidPublicKey < Error; end
  class InvalidPrivateKey < Error; end

  class AggSigContext < FFI::Struct
    layout :data, :int
  end

  class ScratchSpace < FFI::Struct
    layout :data, :int
  end

  class BulletproofGenerators < FFI::Struct
    layout :data, :int
  end

  class Generator < FFI::Struct
    layout :data, [:uchar, 64]
  end

  class Signature < FFI::Struct
    layout :data, [:uchar, 64]
  end

  class RecoverableSignature < FFI::Struct
    layout :data, [:uchar, 65]
  end

  class SharedSecret < FFI::Struct
    layout :data, [:uchar, 32]
  end
end
