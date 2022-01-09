# frozen_string_literal: true

module Secp256k1zkp
  # Secp256k1 context class.
  class Context
    attr_reader :ctx, :caps

    def initialize(caps: Secp256k1zkp::SECP256K1_CONTEXT_FULL)
      @ctx = FFI::AutoPointer.new(C.secp256k1_context_create(caps), C.method(:secp256k1_context_destroy))
      @caps = caps
      if caps?(Secp256k1zkp::SECP256K1_CONTEXT_SIGN)
        err = C.secp256k1_context_randomize(ctx, ::FFI::MemoryPointer.from_string(SecureRandom.random_bytes(32)))
        raise AssertError, 'secp256k1_context_randomize failed.' unless err == 1
      end
    end

    def caps?(caps)
      self.caps == caps
    end
  end
end
