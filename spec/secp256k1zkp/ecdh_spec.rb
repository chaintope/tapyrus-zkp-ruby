# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Secp256k1zkp::ECDH do

  let(:ctx) { Secp256k1zkp::Context.new(caps: Secp256k1zkp::SECP256K1_CONTEXT_SIGN) }

  describe 'SharedSecret' do
    it 'should generate shared secret' do
      key1 = Secp256k1zkp::PrivateKey.generate(ctx)
      key1_pub = key1.public_key(ctx)
      key2 = Secp256k1zkp::PrivateKey.generate(ctx)
      key2_pub = key2.public_key(ctx)
      sec1 = key1.ecdh(ctx, key2_pub)
      sec2 = key2_pub.ecdh(ctx, key1)
      sec_odd = key1.ecdh(ctx, key1_pub)
      expect(sec1).to eq(sec2)
      expect(sec2).not_to eq(sec_odd)
    end
  end
end
