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

    module_function

    # Generate Single-Signer (plain old Schnorr, sans-multisig) signature.
    # @param [Secp256k1zkp::Context] ctx Secp256k1 context.
    # @param [String] msg message to be signed.
    # @param [Secp256k1zkp::PrivateKey] private_key private key.
    # @param [Secp256k1zkp::PrivateKey] priv_nonce private nonce. if nil, generate a nonce.
    # @param [Secp256k1zkp::PrivateKey] extra If not nil, add this key to s.
    # @param [Secp256k1zkp::PublicKey] pub_nonce If not nil, overrides the public nonce to encode as part of e.
    # @param [Secp256k1zkp::PublicKey] publick_key_for_e If not nil, encode this value in e instead of the derived
    # @param [Secp256k1zkp::PublicKey] final_nonce_sum If not nil, overrides the public nonce to encode as part of e
    # @return [Secp256k1zkp::ECDSA::Signature]
    def sign_single(ctx, msg, private_key, priv_nonce: nil, extra: nil, pub_nonce: nil, publick_key_for_e: nil, final_nonce_sum: nil)
      sig = Secp256k1zkp::ECDSA::Signature.new
      msg_ptr = FFI::MemoryPointer.new(:uchar, msg.bytesize).put_bytes(0, msg)
      seed = FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, SecureRandom.bytes(32))
      priv_nonce_ptr = priv_nonce&.pointer
      pub_nonce_ptr = pub_nonce&.pointer
      extra_ptr = extra&.pointer
      publick_key_for_e_ptr = publick_key_for_e&.pointer
      final_nonce_sum_ptr = final_nonce_sum&.pointer
      res = C.secp256k1_aggsig_sign_single(ctx.ctx, sig.pointer, msg_ptr, private_key.pointer, priv_nonce_ptr,
                                           extra_ptr, pub_nonce_ptr, final_nonce_sum_ptr, publick_key_for_e_ptr, seed)
      raise InvalidSignature unless res == 1

      sig
    end

    # Verify Single-Signer (plain old Schnorr, sans-multisig) signature
    # @param [Secp256k1zkp::Context] ctx Secp256k1 context.
    # @param [Secp256k1zkp::ECDSA::Signature] sig signature.
    # @param [String] msg message to be verified.
    # @param [Secp256k1zkp::PublicKey] public_key public key.
    # @param [Boolean] partial whether this is a partial sig, or a fully-combined sig.
    # @param [Secp256k1zkp::PublicKey] pub_nonce If not nil, overrides the public nonce used to calculate e.
    # @param [Secp256k1zkp::PublicKey] pubkey_total If not nil, encode this value in e.
    # @param [Secp256k1zkp::PublicKey] extra_pubkey If not nil, subtract this pubkey from sG.
    # @return [Boolean]
    def valid_single?(ctx, sig, msg, public_key, partial, pub_nonce: nil, pubkey_total: nil, extra_pubkey: nil)
      msg_ptr = FFI::MemoryPointer.new(:uchar, msg.bytesize).put_bytes(0, msg)
      pub_nonce_ptr = pub_nonce&.pointer
      extra_pubkey_ptr = extra_pubkey&.pointer
      pubkey_total_ptr = pubkey_total&.pointer
      is_partial = partial ? 1 : 0
      return false if sig[:data].to_a == Secp256k1zkp::ZERO_256 || public_key[:data].to_a == Secp256k1zkp::ZERO_256

      res = C.secp256k1_aggsig_verify_single(ctx.ctx, sig.pointer, msg_ptr, pub_nonce_ptr, public_key.pointer,
                                             pubkey_total_ptr, extra_pubkey_ptr, is_partial)
      res == 1
    end
  end
end
