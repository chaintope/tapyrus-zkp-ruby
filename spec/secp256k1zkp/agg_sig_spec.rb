require 'spec_helper'

RSpec.describe Secp256k1zkp::AggSig do

  let(:ctx) { Secp256k1zkp::Context.new }

  describe 'AggSig multisig' do
    it do
      key_nums = 5
      private_keys = key_nums.times.map { Secp256k1zkp::PrivateKey.generate(ctx) }

      public_keys = private_keys.map { |k| k.public_key(ctx) }
      # Creating aggsig context with public keys
      agg_ctx = Secp256k1zkp::AggSig::Context.new(ctx, public_keys)
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
      private_key = Secp256k1zkp::PrivateKey.generate(ctx)
      public_key = private_key.public_key(ctx)
      msg = SecureRandom.bytes(32)

      # Signature verification single (correct)
      sig = Secp256k1zkp::AggSig.sign_single(ctx, msg, private_key)
      result = Secp256k1zkp::AggSig.valid_single?(ctx, sig, msg, public_key, false)
      expect(result).to be true

      # Signature verification single (wrong message)
      msg = SecureRandom.bytes(32)
      result = Secp256k1zkp::AggSig.valid_single?(ctx, sig, msg, public_key, false)
      expect(result).to be false

      # test optional extra key
      msg = SecureRandom.bytes(32)
      private_key_extra = Secp256k1zkp::PrivateKey.generate(ctx)
      public_key_extra = private_key_extra.public_key(ctx)
      sig = Secp256k1zkp::AggSig.sign_single(ctx, msg, private_key, extra: private_key_extra)
      result = Secp256k1zkp::AggSig.valid_single?(ctx, sig, msg, public_key, false, extra_pubkey: public_key_extra)
      expect(result).to be true
    end
  end
end
