# frozen_string_literal: true

module Secp256k1zkp

  module ECDSA

    # ECDSA signature
    class Signature < FFI::Struct

      SIZE_SERIALIZED = 72
      SIZE_COMPACT = 64

      layout :data, [:uchar, 64]

      # Convert a DER-encoded bytes to Signature.
      # @param [Secp256k1zkp::Context] ctx Secp256k1 context.
      # @param [String] der DER-encoded signature with binary format.
      # @raise [Secp256k1zkp::InvalidSignature]
      # @return [Secp256k1zkp::ECDSA::Signature]
      def self.from_der(ctx, der)
        signature = Signature.new
        data_ptr = FFI::MemoryPointer.new(:uchar, der.bytesize).put_bytes(0, der)
        res = C.secp256k1_ecdsa_signature_parse_der(ctx.ctx, signature.pointer, data_ptr, data_ptr.size)
        raise InvalidSignature unless res == 1

        signature
      end

      # Convert a compact bytes to Signature.
      # @param [Secp256k1zkp::Context] ctx Secp256k1 context.
      # @param [String] compact signature with binary format.
      # @raise [Secp256k1zkp::InvalidSignature]
      # @return [Secp256k1zkp::ECDSA::Signature]
      def self.from_compact(ctx, compact)
        raise InvalidSignature unless compact.bytesize == SIZE_COMPACT

        signature = Signature.new
        data_ptr = FFI::MemoryPointer.new(:uchar, compact.bytesize).put_bytes(0, compact)
        res = C.secp256k1_ecdsa_signature_parse_compact(ctx.ctx, signature.pointer, data_ptr)
        raise InvalidSignature unless res == 1

        signature
      end

      # Convert signature to DER-encoded signature.
      # @param [Secp256k1zkp::Context] ctx Secp256k1 context.
      # @raise [Secp256k1zkp::AssertError]
      # @return [String] DER-encoded signature
      def to_der(ctx)
        data = FFI::MemoryPointer.new(:uchar, SIZE_SERIALIZED)
        len = FFI::MemoryPointer.new(:size_t).put_uint(0, SIZE_SERIALIZED)
        res = C.secp256k1_ecdsa_signature_serialize_der(ctx.ctx, data, len, pointer)
        raise AssertError, 'secp256k1_ecdsa_signature_serialize_der failed' unless res == 1

        data.read_bytes(len.read_uint)
      end

      # Convert signature to compact format.
      # @param [Secp256k1zkp::Context] ctx Secp256k1 context.
      # @raise [Secp256k1zkp::AssertError]
      # @return [String] Compact signature
      def to_compact(ctx)
        data = FFI::MemoryPointer.new(:uchar, SIZE_COMPACT)
        res = C.secp256k1_ecdsa_signature_serialize_compact(ctx.ctx, data, pointer)
        raise AssertError, 'secp256k1_ecdsa_signature_serialize_compact failed' unless res == 1

        data.read_bytes(SIZE_COMPACT)
      end

      # Normalizes a signature to a "low S" form.
      # @param [Secp256k1zkp::Context] ctx Secp256k1 context.
      def normalize_s!(ctx)
        C.secp256k1_ecdsa_signature_normalize(ctx.ctx, pointer, pointer)
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
