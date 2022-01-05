# frozen_string_literal: true

module Secp256k1zkp

  module ECDSA

    # ECDSA signature
    class Signature < FFI::Struct

      SIZE_SERIALIZED = 72

      layout :data, [:uchar, 64]

      # Converts a DER-encoded bytes to Signature.
      # @param [Secp256k1zkp::Context] ctx Secp256k1 context.
      # @param [String] data DER-encoded signature with binary format.
      # @return [Secp256k1zkp::ECDSA::Signature]
      def self.from_der(ctx, data)
        signature = Signature.new
        data_ptr = FFI::MemoryPointer.new(:uchar, data.bytesize).put_bytes(0, data)
        res = C.secp256k1_ecdsa_signature_parse_der(ctx.ctx, signature.pointer, data_ptr, data_ptr.size)
        raise InvalidSignature unless res == 1

        signature
      end

      # Convert signature to DER-encoded signature.
      # @param [Secp256k1zkp::Context] ctx Secp256k1 context.
      # @return [String] DER-encoded signature
      def to_der(ctx)
        data = FFI::MemoryPointer.new(:uchar, SIZE_SERIALIZED)
        len = FFI::MemoryPointer.new(:size_t).put_uint(0, SIZE_SERIALIZED)
        res = C.secp256k1_ecdsa_signature_serialize_der(ctx.ctx, data, len, self.pointer)
        raise AssertError, 'secp256k1_ecdsa_signature_serialize_der failed' unless res == 1

        data.read_bytes(len.read_uint)
      end

      # Override +==+ to check whether same signature or not.
      # @param [Secp256k1zkp::ECDSA::Signature] other
      # @return [Boolean]
      def ==(other)
        return false unless other.is_a?(Signature)

        self[:data].to_a == other[:data].to_a
      end
    end

    class RecoverableSignature < FFI::Struct
      layout :data, [:uchar, 65]
    end
  end
end
