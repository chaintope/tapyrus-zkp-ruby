# frozen_string_literal: true

module Secp256k1zkp

  module Pedersen

    # Pedersen commitment
    class Commitment < FFI::Struct

      layout :data, [:uchar, 64]

      SIZE = 33 # The size of a Pedersen commitment
      SIZE_INTERNAL = 64 # The size of a Pedersen commitment

      # Generate a Pedersen commitment.
      # @param [Secp256k1zkp::Context] ctx Secp256k1 context.
      # @param [Integer] value value to commit to.
      # @param [Integer] blind blinding factor.
      # @param [Secp256k1zkp::Generator] value_gen value generator 'h'
      # @param [Secp256k1zkp::Generator] blind_gen blinding factor generator 'g'
      # @return [Secp256k1zkp::Pedersen::Commitment]
      # @raise [ArgumentError]
      # @raise [Secp256k1zkp::InvalidFactor]
      def self.generate(ctx, value, blind, value_gen: Secp256k1zkp.generator_h_ptr, blind_gen: Secp256k1zkp.generator_g_ptr)
        raise ArgumentError unless blind.is_a?(Integer)
        raise ArgumentError unless value.is_a?(Integer)

        commitment = Commitment.new
        raw_blind = [blind.to_even_hex(32)].pack('H*')
        raw_blind_ptr = FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, raw_blind)
        res = C.secp256k1_pedersen_commit(ctx.ctx, commitment.pointer, raw_blind_ptr, value, value_gen, blind_gen)
        raise InvalidFactor unless res == 1

        commitment
      end

      # Parse a 33-bytes commitment into a commitment object.
      # @param [Secp256k1zkp::Context] ctx Secp256k1 context.
      # @param [String] hex_commitment 33-bytes serialized commitment key.
      # @return [Secp256k1zkp::Pedersen::Commitment]
      # @raise [Secp256k1zkp::InvalidCommit]
      def self.from_hex(ctx, hex_commitment)
        raw_commit = [hex_commitment].pack('H*')
        raise InvalidCommit if raw_commit.bytesize != SIZE || raw_commit.unpack1('H*') != hex_commitment

        commit_ptr = FFI::MemoryPointer.new(:uchar, SIZE).put_bytes(0, raw_commit)
        commitment = Commitment.new
        res = C.secp256k1_pedersen_commitment_parse(ctx.ctx, commitment.pointer, commit_ptr)
        raise InvalidCommit unless res == 1

        commitment
      end

      # Convert commitment to a serialized hex string.
      # @param [Secp256k1zkp::Context] ctx Secp256k1 context.
      # @return [String] hex string.
      def to_hex(ctx)
        hex_ptr = FFI::MemoryPointer.new(:uchar, SIZE)

        C.secp256k1_pedersen_commitment_serialize(ctx.ctx, hex_ptr, pointer)
        hex_ptr.read_bytes(SIZE).unpack1('H*')
      end

      # Override +==+ to check whether same public key or not.
      # @param [Secp256k1zkp::Pedersen::Commitment] other
      # @return [Boolean]
      def ==(other)
        return false unless other.is_a?(Commitment)

        self[:data].to_a == other[:data].to_a
      end
    end

  end
end
