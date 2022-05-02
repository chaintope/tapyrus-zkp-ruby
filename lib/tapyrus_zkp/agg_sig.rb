# frozen_string_literal: true

module TapyrusZkp
  module AggSig

    SCRATCH_SPACE_SIZE = 1024 * 1024

    class PartialSignature < FFI::Struct
      layout :data, [:uchar, 32]
    end

    # AggSig context
    class Context

      attr_reader :ctx, :agg_ctx

      # @param [TapyrusZkp::Context] ctx Secp256k1 context.
      # @param [Array(TapyrusZkp::PublicKey)] public_keys
      # @return [TapyrusZkp::AggSig::Context]
      def initialize(ctx, public_keys)
        seed = FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, SecureRandom.bytes(32))
        public_keys_ptr = FFI::MemoryPointer.new(TapyrusZkp::PublicKey, public_keys.length)
        public_keys.each_with_index do |p, i|
          public_keys_ptr[i].put_bytes(0, p.pointer.get_bytes(0, TapyrusZkp::PublicKey.size))
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
      # @param [TapyrusZkp::PrivateKey] private_key private key.
      # @param [Integer] index which index to generate a partial sig for.
      # @return [TapyrusZkp::AggSig::PartialSignature]
      # @raise [Secp256k1zkp::PartialSigFailure]
      def partial_sign(msg, private_key, index)
        msg_ptr = FFI::MemoryPointer.new(:uchar, msg.bytesize).put_bytes(0, msg)
        partial_sig = TapyrusZkp::AggSig::PartialSignature.new
        res = C.secp256k1_aggsig_partial_sign(ctx.ctx, agg_ctx, partial_sig.pointer, msg_ptr, private_key.pointer, index)
        raise TapyrusZkp::PartialSigFailure unless res == 1

        partial_sig
      end

      # Aggregate multiple signature parts into a single aggregated signature.
      # @param [Array(TapyrusZkp::AggSig::PartialSignature)]
      # @return [TapyrusZkp::ECDSA::Signature]
      # @raise [Secp256k1zkp::PartialSigFailure]
      def combine_signature(partial_sigs)
        sig = TapyrusZkp::ECDSA::Signature.new
        partial_sigs_ptr = FFI::MemoryPointer.new(TapyrusZkp::AggSig::PartialSignature, partial_sigs.length)
        partial_sigs.each_with_index do |p, i|
          partial_sigs_ptr[i].put_bytes(0, p.pointer.get_bytes(0, TapyrusZkp::AggSig::PartialSignature.size))
        end
        res = C.secp256k1_aggsig_combine_signatures(ctx.ctx, agg_ctx, sig.pointer, partial_sigs_ptr, partial_sigs.length)
        raise TapyrusZkp::PartialSigFailure unless res == 1

        sig
      end

      # Verifies aggregate sig
      # @param [TapyrusZkp::ECDSA::Signature] sig combined signature.
      # @param [String] msg message to be verified.
      # @param [Array(TapyrusZkp::PublicKey)] public_keys public keys.
      def valid_sig?(sig, msg, public_keys)
        msg_ptr = FFI::MemoryPointer.new(:uchar, msg.bytesize).put_bytes(0, msg)
        public_keys_ptr = FFI::MemoryPointer.new(TapyrusZkp::PublicKey, public_keys.length)
        public_keys.each_with_index do |p, i|
          public_keys_ptr[i].put_bytes(0, p.pointer.get_bytes(0, TapyrusZkp::PublicKey.size))
        end
        res = C.secp256k1_aggsig_build_scratch_and_verify(ctx.ctx, sig.pointer, msg_ptr, public_keys_ptr, public_keys.length)
        res == 1
      end
    end

    module_function

    # Generate Single-Signer (plain old Schnorr, sans-multisig) signature.
    # @param [TapyrusZkp::Context] ctx Secp256k1 context.
    # @param [String] msg message to be signed.
    # @param [TapyrusZkp::PrivateKey] private_key private key.
    # @param [TapyrusZkp::PrivateKey] secnonce private nonce. if nil, generate a nonce.
    # @param [TapyrusZkp::PrivateKey] extra If not nil, add this key to s.
    # @param [TapyrusZkp::PublicKey] pubnonce If not nil, overrides the public nonce to encode as part of e.
    # @param [TapyrusZkp::PublicKey] publick_key_for_e If not nil, encode this value in e instead of the derived
    # @param [TapyrusZkp::PublicKey] final_nonce_sum If not nil, overrides the public nonce to encode as part of e
    # @return [TapyrusZkp::ECDSA::Signature]
    def sign_single(ctx, msg, private_key, secnonce: nil, extra: nil, pubnonce: nil, publick_key_for_e: nil, final_nonce_sum: nil)
      sig = TapyrusZkp::ECDSA::Signature.new
      msg_ptr = FFI::MemoryPointer.new(:uchar, msg.bytesize).put_bytes(0, msg)
      seed = FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, SecureRandom.bytes(32))
      priv_nonce_ptr = secnonce&.pointer
      pub_nonce_ptr = pubnonce&.pointer
      extra_ptr = extra&.pointer
      publick_key_for_e_ptr = publick_key_for_e&.pointer
      final_nonce_sum_ptr = final_nonce_sum&.pointer
      res = C.secp256k1_aggsig_sign_single(ctx.ctx, sig.pointer, msg_ptr, private_key.pointer, priv_nonce_ptr,
                                           extra_ptr, pub_nonce_ptr, final_nonce_sum_ptr, publick_key_for_e_ptr, seed)
      raise InvalidSignature unless res == 1

      sig
    end

    # Verify Single-Signer (plain old Schnorr, sans-multisig) signature
    # @param [TapyrusZkp::Context] ctx Secp256k1 context.
    # @param [TapyrusZkp::ECDSA::Signature] sig signature.
    # @param [String] msg message to be verified.
    # @param [TapyrusZkp::PublicKey] public_key public key.
    # @param [Boolean] partial whether this is a partial sig, or a fully-combined sig.
    # @param [TapyrusZkp::PublicKey] pubnonce If not nil, overrides the public nonce used to calculate e.
    # @param [TapyrusZkp::PublicKey] pubkey_total If not nil, encode this value in e.
    # @param [TapyrusZkp::PublicKey] extra_pubkey If not nil, subtract this pubkey from sG.
    # @return [Boolean]
    def valid_single?(ctx, sig, msg, public_key, partial, pubnonce: nil, pubkey_total: nil, extra_pubkey: nil)
      msg_ptr = FFI::MemoryPointer.new(:uchar, msg.bytesize).put_bytes(0, msg)
      pub_nonce_ptr = pubnonce&.pointer
      extra_pubkey_ptr = extra_pubkey&.pointer
      pubkey_total_ptr = pubkey_total&.pointer
      is_partial = partial ? 1 : 0
      return false if sig[:data].to_a == TapyrusZkp::ZERO_256 || public_key[:data].to_a == TapyrusZkp::ZERO_256

      res = C.secp256k1_aggsig_verify_single(ctx.ctx, sig.pointer, msg_ptr, pub_nonce_ptr, public_key.pointer,
                                             pubkey_total_ptr, extra_pubkey_ptr, is_partial)
      res == 1
    end

    # Generates and exports a secure nonce, of which the public part can be shared and fed back for a later signature.
    # @param [TapyrusZkp::Context] ctx Secp256k1 context.
    # @return [TapyrusZkp::PrivateKey]
    # @raise [Secp256k1zkp::AssertError]
    def export_secnonce_single(ctx)
      secnonce = FFI::MemoryPointer.new(:uchar, 32)
      seed = FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, SecureRandom.bytes(32))
      res = C.secp256k1_aggsig_export_secnonce_single(ctx.ctx, secnonce, seed)
      raise AssertError, 'secp256k1_aggsig_export_secnonce_single failed' unless res == 1

      TapyrusZkp::PrivateKey.new(ctx, secnonce.read_bytes(32))
    end

    # Simple addition of two signatures + two public nonces into a single signature
    # @param [TapyrusZkp::Context] ctx Secp256k1 context.
    # @param [Array(TapyrusZkp::ECDSA::Signature)] sigs sig1 and sig2 to be added.
    # @param [TapyrusZkp::PublicKey] pubnoce_total sum of public nonces
    # @return [TapyrusZkp::ECDSA::Signature]
    # @raise [InvalidSignature]
    def add_signatures_single(ctx, sigs, pubnoce_total)
      sig = TapyrusZkp::ECDSA::Signature.new
      sigs_ptr = FFI::MemoryPointer.new(:pointer, sigs.length)
      sigs.each_with_index do |sig, i|
        sigs_ptr[i].put_pointer(0, sig.pointer)
      end
      res = C.secp256k1_aggsig_add_signatures_single(ctx.ctx, sig.pointer, sigs_ptr, sigs.length, pubnoce_total.pointer)
      raise InvalidSignature unless res == 1

      sig
    end

    # Batch Schnorr signature verification
    # @param [TapyrusZkp::Context] ctx Secp256k1 context.
    # @param [Array(TapyrusZkp::ECDSA::Signature)] sigs
    # @param [Array(String)] msgs
    # @param [Array(TapyrusZkp::PublicKey)] public_keys
    # @return [Boolean]
    def verify_batch(ctx, sigs, msgs, public_keys)
      return false if sigs.length != msgs.length || msgs.length != public_keys.length

      sigs_ptr = FFI::MemoryPointer.new(:pointer, sigs.length)
      sigs.each_with_index do |sig, i|
        sigs_ptr[i].put_pointer(0, sig.pointer)
      end
      msgs_ptr = FFI::MemoryPointer.new(:pointer, msgs.length)
      msgs.each_with_index do |msg, i|
        msgs_ptr[i].put_pointer(0, FFI::MemoryPointer.new(:uchar, msg.bytesize).put_bytes(0, msg))
      end
      public_keys_ptr = FFI::MemoryPointer.new(:pointer, public_keys.length)
      public_keys.each_with_index do |public_key, i|
        public_keys_ptr[i].put_pointer(0, public_key.pointer)
      end
      space = TapyrusZkp.create_scratch_space(ctx, SCRATCH_SPACE_SIZE)
      res = C.secp256k1_schnorrsig_verify_batch(ctx.ctx, space, sigs_ptr, msgs_ptr, public_keys_ptr, sigs.length)
      res == 1
    end
  end
end
