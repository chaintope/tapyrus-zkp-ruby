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

end
