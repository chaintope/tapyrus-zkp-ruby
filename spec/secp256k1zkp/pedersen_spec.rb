# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Secp256k1zkp::Pedersen do

  let(:ctx) { Secp256k1zkp::Context.new(caps: Secp256k1zkp::SECP256K1_CONTEXT_COMMIT) }

  describe 'Commitment#from_hex and #to_hex' do
    it do
      hex_commitment = '09c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5'
      commit = Secp256k1zkp::Pedersen::Commitment.from_hex(ctx, hex_commitment)
      expect(commit.to_hex(ctx)).to eq(hex_commitment)
    end

    context 'Invalid commitment' do
      it 'should raise error' do
        hex_commitment = '9c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5'
        expect { Secp256k1zkp::Pedersen::Commitment.from_hex(ctx, hex_commitment) }.to raise_error(Secp256k1zkp::InvalidCommit)
      end
    end
  end

  describe 'Commitment#generate' do
    it 'should generate commitment' do
      value = 1
      blind1 = SecureRandom.hex(32).to_i(16)
      blind2 = 1
      commit1 = Secp256k1zkp::Pedersen::Commitment.generate(ctx, value, blind1)
      commit2 = Secp256k1zkp::Pedersen::Commitment.generate(ctx, blind2, blind1)
      expect(commit1).to eq(commit2)
      value = 2
      commit1 = Secp256k1zkp::Pedersen::Commitment.generate(ctx, value, blind1)
      commit2 = Secp256k1zkp::Pedersen::Commitment.generate(ctx, blind2, blind1)
      expect(commit1).not_to eq(commit2)
    end
  end
end
