# frozen_string_literal: true

module Secp256k1zkp

  module Bulletproof

    MAX_WIDTH = 1 << 20
    SCRATCH_SPACE_SIZE = 256 * MAX_WIDTH
    MAX_GENERATORS = 256
    # The size of a single Bullet proof
    SINGLE_BULLET_PROOF_SIZE = 675
    MAX_PROOF_SIZE = SINGLE_BULLET_PROOF_SIZE
    # The maximum size of an optional message embedded in a bullet proof
    MSG_SIZE = 20

    @shared_generators = nil

    # A range proof.
    class RangeProof
      attr_reader :proof

      def initialize(proof)
        @proof = proof
      end

      # Get proof byte size
      # @return [Integer]
      def bytesize
        proof.bytesize
      end

      # Generate FFI::MemoryPointer from proof.
      # @return [FFI::MemoryPointer]
      def pointer
        FFI::MemoryPointer.new(:uchar, proof.bytesize).put_bytes(0, proof)
      end
    end

    module_function

    # Get shared generators
    # @param [Secp256k1zkp::Context] ctx Secp256k1 context.
    def shared_generators(ctx)
      return @shared_generators if @shared_generators

      @shared_generators = C.secp256k1_bulletproof_generators_create(ctx.ctx, Secp256k1zkp.generator_g_ptr, MAX_GENERATORS)
      @shared_generators
    end

    # Produces a bullet proof for the provided +value+, using min and max bounds, relying on the blinding factor and value.
    # If a +msg+ is passed, it will be truncated or padded to exactly BULLET_PROOF_MSG_SIZE bytes.
    # @param [Secp256k1zkp::Context] ctx Secp256k1 context.
    # @param [Integer] value value
    # @param [Integer] blind blinding factor.
    # @param [Integer] rewind_nonce random seed used to derive blinding factors
    # @param [Integer] private_nonce
    # @param [String] extra_data additional data committed to by the range proof.
    # @param [String] msg optional 20 bytes of message that can be recovered by rewinding with the correct nonce.
    # @return [Secp256k1zkp::Bulletproof::RangeProof]
    # @raise [ArgumentError]
    # @raise [Secp256k1zkp::AssertError]
    def generate(ctx, value, blind, rewind_nonce, private_nonce, extra_data: nil, msg: nil)
      raise ArgumentError, 'value must be Integer' unless value.is_a?(Integer)
      raise ArgumentError, 'blind must be Integer' unless blind.is_a?(Integer)
      raise ArgumentError, 'rewind_nonce must be Integer' unless rewind_nonce.is_a?(Integer)
      raise ArgumentError, 'private_nonce must be Integer' unless private_nonce.is_a?(Integer)
      raise ArgumentError, 'msg must be 20 bytes or less.' if msg && msg.bytesize > MSG_SIZE

      proof = FFI::MemoryPointer.new(:uchar, MAX_PROOF_SIZE)
      proof_len = FFI::MemoryPointer.new(:size_t).put_uint(0, MAX_PROOF_SIZE)
      value_ptr = FFI::MemoryPointer.new(:uint).put_uint(0, value)
      blind_ptr = FFI::MemoryPointer.new(:pointer, 1)
      blind_ptr[0].put_pointer(0, FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, [blind.to_even_hex(32)].pack('H*')))
      rewind_ptr = FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, [rewind_nonce.to_even_hex(32)].pack('H*'))
      private_ptr = FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, [private_nonce.to_even_hex(32)].pack('H*'))
      extra_ptr = extra_data ? FFI::MemoryPointer.new(:uchar, extra_data.bytesize).put_bytes(0, extra_data) : nil
      msg_ptr = if msg
                  padding = ['00' * (MSG_SIZE - msg.bytesize)].pack('H*')
                  FFI::MemoryPointer.new(:uchar, MSG_SIZE).put_bytes(0, extra_data + padding)
                else
                  nil
                end
      space = Secp256k1zkp.create_scratch_space(ctx, SCRATCH_SPACE_SIZE)
      res = C.secp256k1_bulletproof_rangeproof_prove(
        ctx.ctx,
        space,
        shared_generators(ctx),
        proof,
        proof_len,
        nil,
        nil,
        nil,
        value_ptr,
        nil,
        blind_ptr,
        nil,
        1,
        Secp256k1zkp.generator_h_ptr,
        64,
        rewind_ptr,
        private_ptr,
        extra_ptr,
        extra_data ? extra_data.bytesize : 0,
        msg_ptr
      )
      raise AssertError, 'secp256k1_bulletproof_rangeproof_prove failed' unless res == 1

      RangeProof.new(proof.read_bytes(proof_len.read_int))
    end

    # Verify with bullet proof that a committed value is positive
    # @param [Secp256k1zkp::Context] ctx Secp256k1 context.
    # @param [Secp256k1zkp::Pedersen::Commitment] commit commitment for value.
    # @param [Secp256k1zkp::Bulletproof::RangeProof] proof range proof
    # @param [String] extra_data additional data committed to by the range proof.
    # @return [Boolean]
    def valid_bullet_proof?(ctx, commit, proof, extra_data: nil)
      raise ArgumentError, 'commit must be Secp256k1zkp::Pedersen::Commitment' unless commit.is_a?(Pedersen::Commitment)
      raise ArgumentError, 'proof must be Secp256k1zkp::Bulletproof::RangeProof' unless proof.is_a?(RangeProof)

      extra_ptr = extra_data ? FFI::MemoryPointer.new(:uchar, extra_data.bytesize).put_bytes(0, extra_data) : nil
      space = Secp256k1zkp.create_scratch_space(ctx, SCRATCH_SPACE_SIZE)
      res = C.secp256k1_bulletproof_rangeproof_verify(
        ctx.ctx,
        space,
        shared_generators(ctx),
        proof.pointer,
        proof.bytesize,
        nil,
        commit,
        1,
        64,
        Secp256k1zkp.generator_h_ptr,
        extra_ptr,
        extra_data ? extra_data.bytesize : 0
      )
      res == 1
    end
  end

end
