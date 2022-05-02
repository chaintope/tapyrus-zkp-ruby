# frozen_string_literal: true

require 'spec_helper'

RSpec.describe TapyrusZkp::AggSig do

  let(:ctx) { TapyrusZkp::Context.new }

  describe 'AggSig multisig' do
    it do
      key_nums = 5
      private_keys = key_nums.times.map { TapyrusZkp::PrivateKey.generate(ctx) }

      public_keys = private_keys.map { |k| k.public_key(ctx) }
      # Creating aggsig context with public keys
      agg_ctx = TapyrusZkp::AggSig::Context.new(ctx, public_keys)
      # Generating nonces for each index
      key_nums.times do |i|
        agg_ctx.generate_nonce(i)
      end

      msg = SecureRandom.bytes(32)
      partial_sigs = private_keys.map.with_index do |k, i|
        agg_ctx.partial_sign(msg, k, i)
      end
      # Combined sig
      combined_sig = agg_ctx.combine_signature(partial_sigs)
      expect(agg_ctx.valid_sig?(combined_sig, msg, public_keys)).to be true
    end
  end

  describe 'Aggsig single' do
    it do
      private_key = TapyrusZkp::PrivateKey.generate(ctx)
      public_key = private_key.public_key(ctx)
      msg = SecureRandom.bytes(32)

      # Signature verification single (correct)
      sig = TapyrusZkp::AggSig.sign_single(ctx, msg, private_key)
      result = TapyrusZkp::AggSig.valid_single?(ctx, sig, msg, public_key, false)
      expect(result).to be true

      # Signature verification single (wrong message)
      msg = SecureRandom.bytes(32)
      result = TapyrusZkp::AggSig.valid_single?(ctx, sig, msg, public_key, false)
      expect(result).to be false

      # test optional extra key
      msg = SecureRandom.bytes(32)
      private_key_extra = TapyrusZkp::PrivateKey.generate(ctx)
      public_key_extra = private_key_extra.public_key(ctx)
      sig = TapyrusZkp::AggSig.sign_single(ctx, msg, private_key, extra: private_key_extra)
      result = TapyrusZkp::AggSig.valid_single?(ctx, sig, msg, public_key, false, extra_pubkey: public_key_extra)
      expect(result).to be true
    end
  end

  describe 'Aggsig exchange' do
    it do
      20.times do
        sender_private, sender_pub = TapyrusZkp::PrivateKey.generate_keypair(ctx)
        receiver_private, receiver_pub = TapyrusZkp::PrivateKey.generate_keypair(ctx)

        sender_secnonce = TapyrusZkp::AggSig.export_secnonce_single(ctx)
        receiver_secnonce = TapyrusZkp::AggSig.export_secnonce_single(ctx)

        # Get total nonce
        nonce_sum = receiver_secnonce.public_key(ctx).dup
        nonce_sum.tweak_add!(ctx, sender_secnonce.to_i)

        msg = SecureRandom.bytes(32)

        # Add public keys (for storing in e)
        pubkey_sum = receiver_pub.dup
        pubkey_sum.tweak_add!(ctx, sender_private.to_i)

        # Sender sign
        sender_sig = TapyrusZkp::AggSig.sign_single(
          ctx, msg, sender_private, secnonce: sender_secnonce,
          pubnonce: nonce_sum, publick_key_for_e: pubkey_sum, final_nonce_sum: nonce_sum
        )
        # Receiver verifies sender's signature
        result = TapyrusZkp::AggSig.valid_single?(ctx, sender_sig, msg, sender_pub, true,
                                                  pubnonce: nonce_sum, pubkey_total: pubkey_sum)
        expect(result).to be true

        # Receiver sign
        receiver_sig = TapyrusZkp::AggSig.sign_single(
          ctx, msg, receiver_private, secnonce: receiver_secnonce,
          pubnonce: nonce_sum, publick_key_for_e: pubkey_sum, final_nonce_sum: nonce_sum
        )
        # Sender verifies receiver's signature
        result = TapyrusZkp::AggSig.valid_single?(ctx, receiver_sig, msg, receiver_pub, true,
                                                  pubnonce: nonce_sum, pubkey_total: pubkey_sum)
        expect(result).to be true

        # calculates final sig
        final_sig = TapyrusZkp::AggSig.add_signatures_single(ctx, [sender_sig, receiver_sig], nonce_sum)
        # verify final sig
        result = TapyrusZkp::AggSig.valid_single?(ctx, final_sig, msg, pubkey_sum, false, pubkey_total: pubkey_sum)
        expect(result).to be true
      end
    end
  end

  describe 'Aggsig batch' do
    it do
      sigs = []
      msgs = []
      public_keys = []

      100.times do
        private_key, public_key = TapyrusZkp::PrivateKey.generate_keypair(ctx)
        msg = SecureRandom.bytes(32)
        sig = TapyrusZkp::AggSig.sign_single(ctx, msg, private_key, publick_key_for_e: public_key)
        result = TapyrusZkp::AggSig.valid_single?(ctx, sig, msg, public_key, false, pubkey_total: public_key)
        expect(result).to be true
        public_keys << public_key
        sigs << sig
        msgs << msg
      end

      # verify aggsig batch
      result = TapyrusZkp::AggSig.verify_batch(ctx, sigs, msgs, public_keys)
      expect(result).to be true
    end
  end
end
