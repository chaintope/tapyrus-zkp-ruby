# frozen_string_literal: true

module Secp256k1zkp
  module AggSig

    class PartialSignature < FFI::Struct
      layout :data, [:uchar, 32]
    end

    # AggSig context
    class Context

      attr_reader :ctx, :agg_ctx

      # @param [Secp256k1zkp::Context] ctx Secp256k1 context.
      # @param [Array(Secp256k1zkp::PublicKey)] public_keys
      # @return [Secp256k1zkp::AggSig::Context]
      def initialize(ctx, public_keys)
        seed = FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, SecureRandom.bytes(32))
        public_keys_ptr = FFI::MemoryPointer.new(Secp256k1zkp::PublicKey, public_keys.length)
        public_keys.each_with_index do |p, i|
          public_keys_ptr[i].put_bytes(0, p.pointer.get_bytes(0, Secp256k1zkp::PublicKey.size))
        end

        @agg_ctx = FFI::AutoPointer.new(
          C.secp256k1_aggsig_context_create(ctx.ctx, public_keys_ptr, public_keys.length, seed),
          C.method(:secp256k1_aggsig_context_destroy)
        )
        @ctx = ctx
      end

      # Generate a nonce pair for a single signature part in an aggregated signature.
      # @param [Integer] index which signature to generate a nonce for.
      # @raise [Secp256k1zkp::AssertError]
      def generate_nonce(index)
        res = C.secp256k1_aggsig_generate_nonce(ctx.ctx, agg_ctx, index)
        raise AssertError, 'secp256k1_aggsig_generate_nonce failed' unless res == 1
      end

      # Generate a single signature part in an aggregated signature.
      # @param [String] msg message to be signed.
      # @param [Secp256k1zkp::PrivateKey] private_key private key.
      # @param [Integer] index which index to generate a partial sig for.
      # @return [Secp256k1zkp::AggSig::PartialSignature]
      # @raise [Secp256k1zkp::PartialSigFailure]
      def partial_sign(msg, private_key, index)
        msg_ptr = FFI::MemoryPointer.new(:uchar, msg.bytesize).put_bytes(0, msg)
        partial_sig = Secp256k1zkp::AggSig::PartialSignature.new
        res = C.secp256k1_aggsig_partial_sign(ctx.ctx, agg_ctx, partial_sig.pointer, msg_ptr, private_key.pointer, index)
        raise Secp256k1zkp::PartialSigFailure unless res == 1

        partial_sig
      end

      # Aggregate multiple signature parts into a single aggregated signature.
      # @param [Array(Secp256k1zkp::AggSig::PartialSignature)]
      # @return [Secp256k1zkp::ECDSA::Signature]
      # @raise [Secp256k1zkp::PartialSigFailure]
      def combine_signature(partial_sigs)
        sig = Secp256k1zkp::ECDSA::Signature.new
        partial_sigs_ptr = FFI::MemoryPointer.new(Secp256k1zkp::AggSig::PartialSignature, partial_sigs.length)
        partial_sigs.each_with_index do |p, i|
          partial_sigs_ptr[i].put_bytes(0, p.pointer.get_bytes(0, Secp256k1zkp::AggSig::PartialSignature.size))
        end
        res = C.secp256k1_aggsig_combine_signatures(ctx.ctx, agg_ctx, sig.pointer, partial_sigs_ptr, partial_sigs.length)
        raise Secp256k1zkp::PartialSigFailure unless res == 1

        sig
      end

      # Verifies aggregate sig
      # @param [Secp256k1zkp::ECDSA::Signature] sig combined signature.
      # @param [String] msg message to be verified.
      # @param [Array(Secp256k1zkp::PublicKey)] public_keys public keys.
      def valid_sig?(sig, msg, public_keys)
        msg_ptr = FFI::MemoryPointer.new(:uchar, msg.bytesize).put_bytes(0, msg)
        public_keys_ptr = FFI::MemoryPointer.new(Secp256k1zkp::PublicKey, public_keys.length)
        public_keys.each_with_index do |p, i|
          public_keys_ptr[i].put_bytes(0, p.pointer.get_bytes(0, Secp256k1zkp::PublicKey.size))
        end
        res = C.secp256k1_aggsig_build_scratch_and_verify(ctx.ctx, sig.pointer, msg_ptr, public_keys_ptr, public_keys.length)
        res == 1
      end
    end

  end
end
