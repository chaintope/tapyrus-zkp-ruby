# frozen_string_literal: true

module TapyrusZkp

  module ECDSA

    # ECDSA signature
    class Signature < FFI::Struct

      SIZE_SERIALIZED = 72
      SIZE_COMPACT = 64

      layout :data, [:uchar, 64]

      # Convert a DER-encoded bytes to Signature.
      # @param [TapyrusZkp::Context] ctx Secp256k1 context.
      # @param [String] der DER-encoded signature with binary format.
      # @raise [Secp256k1zkp::InvalidSignature]
      # @return [TapyrusZkp::ECDSA::Signature]
      def self.from_der(ctx, der)
        signature = Signature.new
        data_ptr = FFI::MemoryPointer.new(:uchar, der.bytesize).put_bytes(0, der)
        res = C.secp256k1_ecdsa_signature_parse_der(ctx.ctx, signature.pointer, data_ptr, data_ptr.size)
        raise InvalidSignature unless res == 1

        signature
      end

      # Convert a compact bytes to Signature.
      # @param [TapyrusZkp::Context] ctx Secp256k1 context.
      # @param [String] compact signature with binary format.
      # @raise [Secp256k1zkp::InvalidSignature]
      # @return [TapyrusZkp::ECDSA::Signature]
      def self.from_compact(ctx, compact)
        raise InvalidSignature unless compact.bytesize == SIZE_COMPACT

        signature = Signature.new
        data_ptr = FFI::MemoryPointer.new(:uchar, compact.bytesize).put_bytes(0, compact)
        res = C.secp256k1_ecdsa_signature_parse_compact(ctx.ctx, signature.pointer, data_ptr)
        raise InvalidSignature unless res == 1

        signature
      end

      # Convert signature to DER-encoded signature.
      # @param [TapyrusZkp::Context] ctx Secp256k1 context.
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
      # @param [TapyrusZkp::Context] ctx Secp256k1 context.
      # @raise [Secp256k1zkp::AssertError]
      # @return [String] Compact signature
      def to_compact(ctx)
        data_ptr = FFI::MemoryPointer.new(:uchar, SIZE_COMPACT)
        res = C.secp256k1_ecdsa_signature_serialize_compact(ctx.ctx, data_ptr, pointer)
        raise AssertError, 'secp256k1_ecdsa_signature_serialize_compact failed' unless res == 1

        data_ptr.read_bytes(SIZE_COMPACT)
      end

      # Normalizes a signature to a "low S" form.
      # @param [TapyrusZkp::Context] ctx Secp256k1 context.
      def normalize_s!(ctx)
        C.secp256k1_ecdsa_signature_normalize(ctx.ctx, pointer, pointer)
      end

      # Override +==+ to check whether same signature or not.
      # @param [TapyrusZkp::ECDSA::Signature] other
      # @return [Boolean]
      def ==(other)
        return false unless other.is_a?(Signature)

        self[:data].to_a == other[:data].to_a
      end
    end

    # Recoverable ECDSA signature
    # Note: This class can only be used if the libsecp256k1-zkp recovery module is enabled.
    class RecoverableSignature < FFI::Struct
      layout :data, [:uchar, 65]

      # Convert a compact-encoded byte slice to a signature.
      # @param [TapyrusZkp::Context] ctx Secp256k1 context.
      # @param [String] compact signature with binary format.
      # @param [Integer] rec_id recovery id.
      # @return [TapyrusZkp::ECDSA::RecoverableSignature]
      def self.from_compact(ctx, compact, rec_id)
        raise InvalidSignature unless compact.bytesize == Signature::SIZE_COMPACT

        data_ptr = FFI::MemoryPointer.new(:uchar, compact.bytesize).put_bytes(0, compact)
        signature = TapyrusZkp::ECDSA::RecoverableSignature.new
        res = C.secp256k1_ecdsa_recoverable_signature_parse_compact(ctx.ctx, signature.pointer, data_ptr, rec_id)
        raise InvalidSignature unless res == 1

        signature
      end

      # Convert the recoverable signature in compact format
      # @param [TapyrusZkp::Context] ctx Secp256k1 context.
      # @return [Array(rec_id, compact)]
      # @raise [Secp256k1zkp::AssertError]
      def to_compact(ctx)
        data_ptr = FFI::MemoryPointer.new(:uchar, Signature::SIZE_COMPACT)
        rec_id_ptr = FFI::MemoryPointer.new(:int)
        res = C.secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx.ctx, data_ptr, rec_id_ptr, pointer)
        raise AssertError, 'secp256k1_ecdsa_recoverable_signature_serialize_compact failed' unless res == 1

        [rec_id_ptr.read_int, data_ptr.read_bytes(Signature::SIZE_COMPACT)]
      end

      # Convert recoverable signature to normal signature.
      # @param [TapyrusZkp::Context] ctx Secp256k1 context.
      # @return [TapyrusZkp::ECDSA::Signature]
      # @raise [Secp256k1zkp::AssertError]
      def to_standard(ctx)
        standard = Signature.new
        res = C.secp256k1_ecdsa_recoverable_signature_convert(ctx.ctx, standard.pointer, pointer)
        raise AssertError, 'secp256k1_ecdsa_recoverable_signature_convert failed' unless res == 1

        standard
      end

      # Determines the public key for which `sig` is a valid signature for +msg+.
      # @param [TapyrusZkp::Context] ctx Secp256k1 context.
      # @param [String] msg message with binary format.
      # @return [TapyrusZkp::PublicKey]
      # @raise [Secp256k1zkp::InvalidSignature]
      def recover(ctx, msg)
        msg_ptr = FFI::MemoryPointer.new(:uchar, msg.bytesize).put_bytes(0, msg)
        public_key = TapyrusZkp::PublicKey.new
        res = C.secp256k1_ecdsa_recover(ctx.ctx, public_key.pointer, pointer, msg_ptr)
        raise InvalidSignature unless res == 1

        public_key
      end

      # Override +==+ to check whether same signature or not.
      # @param [TapyrusZkp::ECDSA::Signature] other
      # @return [Boolean]
      def ==(other)
        return false unless other.is_a?(RecoverableSignature)

        self[:data].to_a == other[:data].to_a
      end
    end
  end
end
