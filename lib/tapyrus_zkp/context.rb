# frozen_string_literal: true

module TapyrusZkp
  # Secp256k1 context class.
  class Context
    attr_reader :ctx, :caps

    def initialize(caps: TapyrusZkp::SECP256K1_CONTEXT_FULL)
      @ctx = FFI::AutoPointer.new(C.secp256k1_context_create(caps), C.method(:secp256k1_context_destroy))
      @caps = caps
      if caps?(TapyrusZkp::SECP256K1_CONTEXT_SIGN)
        err = C.secp256k1_context_randomize(ctx, ::FFI::MemoryPointer.from_string(SecureRandom.random_bytes(32)))
        raise AssertError, 'secp256k1_context_randomize failed.' unless err == 1
      end
    end

    def caps?(caps)
      self.caps == caps
    end
  end

  module_function

  # Create Scratch space pointer
  # @param [TapyrusZkp::Context] ctx Secp256k1 context.
  # @param [Integer] size size of scratch space.
  # @return [FFI::MemoryPointer]
  def create_scratch_space(ctx, size)
    FFI::AutoPointer.new(C.secp256k1_scratch_space_create(ctx.ctx, size), C.method(:secp256k1_scratch_space_destroy))
  end
end
