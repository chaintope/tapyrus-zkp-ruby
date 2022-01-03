module Secp256k1zkp
  # Secp256k1 context class.
  class Context
    attr_reader :ctx

    def initialize(flags: Secp256k1zkp::SECP256K1_CONTEXT_FULL)
      @ctx = FFI::AutoPointer.new(C.secp256k1_context_create(flags), C.method(:secp256k1_context_destroy))
      err = C.secp256k1_context_randomize(ctx, ::FFI::MemoryPointer.from_string(SecureRandom.random_bytes(32)))
      raise Error, 'secp256k1_context_randomize failed.' unless err == 1
    end

  end
end
