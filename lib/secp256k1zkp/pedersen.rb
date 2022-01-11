# frozen_string_literal: true

module Secp256k1zkp

  module Pedersen

    # Pedersen commitment
    class Commitment < FFI::Struct

      layout :data, [:uchar, 64]

      SIZE = 33 # The size of a Pedersen commitment
      SIZE_INTERNAL = 64 # The size of a Pedersen commitment

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
    end

  end
end
