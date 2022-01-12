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

  describe 'Commitment#blind_sum' do
    it 'should generate sum of blind commitment' do
      blind_a = SecureRandom.hex(32).to_i(16)
      blind_b = SecureRandom.hex(32).to_i(16)

      commit_a = Secp256k1zkp::Pedersen::Commitment.generate(ctx, 3, blind_a)
      commit_b = Secp256k1zkp::Pedersen::Commitment.generate(ctx, 2, blind_b)
      blind_c = Secp256k1zkp::Pedersen::Commitment.blind_sum(ctx, [blind_a, blind_b], [])
      commit_c = Secp256k1zkp::Pedersen::Commitment.generate(ctx, 3 + 2, blind_c)
      commit_d = Secp256k1zkp::Pedersen::Commitment.commit_sum(ctx, [commit_a, commit_b], [])
      expect(commit_c).to eq(commit_d)

      blind_e = Secp256k1zkp::Pedersen::Commitment.blind_sum(ctx, [blind_a], [blind_b])
      commit_e = Secp256k1zkp::Pedersen::Commitment.generate(ctx, 3 - 2, blind_e)
      commit_f = Secp256k1zkp::Pedersen::Commitment.commit_sum(ctx, [commit_a], [commit_b])
      expect(commit_e).to eq(commit_f)
    end
  end

  describe 'Commitment#valid_commit_sum?' do
    context 'one key' do
      it do
        commit1 = Secp256k1zkp::Pedersen::Commitment.generate(ctx, 5, 1)
        commit2 = Secp256k1zkp::Pedersen::Commitment.generate(ctx, 5, 1)
        expect(Secp256k1zkp::Pedersen::Commitment.valid_commit_sum?(ctx, [commit1], [commit2])).to be true

        commit1 = Secp256k1zkp::Pedersen::Commitment.generate(ctx, 3, 1)
        commit2 = Secp256k1zkp::Pedersen::Commitment.generate(ctx, 2, 1)
        commit3 = Secp256k1zkp::Pedersen::Commitment.generate(ctx, 5, 1)
        expect(Secp256k1zkp::Pedersen::Commitment.valid_commit_sum?(ctx, [commit1, commit2], [commit3])).to be false

        two_key = Secp256k1zkp::Pedersen::Commitment.blind_sum(ctx, [1, 1], [])
        commit3 = Secp256k1zkp::Pedersen::Commitment.generate(ctx, 5, two_key)
        expect(Secp256k1zkp::Pedersen::Commitment.valid_commit_sum?(ctx, [commit1, commit2], [commit3])).to be true
      end
    end

    context 'zero key' do
      it do
        commit1 = Secp256k1zkp::Pedersen::Commitment.generate(ctx, 5, 0)
        commit2 = Secp256k1zkp::Pedersen::Commitment.generate(ctx, 5, 0)
        expect(Secp256k1zkp::Pedersen::Commitment.valid_commit_sum?(ctx, [commit1], [commit2])).to be true
        commit1 = Secp256k1zkp::Pedersen::Commitment.generate(ctx, 3, 0)
        commit2 = Secp256k1zkp::Pedersen::Commitment.generate(ctx, 2, 0)
        commit3 = Secp256k1zkp::Pedersen::Commitment.generate(ctx, 5, 0)
        expect(Secp256k1zkp::Pedersen::Commitment.valid_commit_sum?(ctx, [commit1, commit2], [commit3])).to be true
        commit1 = Secp256k1zkp::Pedersen::Commitment.generate(ctx, 2, 0)
        commit2 = Secp256k1zkp::Pedersen::Commitment.generate(ctx, 4, 0)
        commit3 = Secp256k1zkp::Pedersen::Commitment.generate(ctx, 1, 0)
        commit4 = Secp256k1zkp::Pedersen::Commitment.generate(ctx, 5, 0)
        expect(Secp256k1zkp::Pedersen::Commitment.valid_commit_sum?(ctx, [commit1, commit2], [commit3, commit4])).to be true
      end
    end

    context 'random key' do
      it do
        blind_pos = SecureRandom.hex(32).to_i(16)
        blind_neg = SecureRandom.hex(32).to_i(16)
        blind_sum = Secp256k1zkp::Pedersen::Commitment.blind_sum(ctx, [blind_pos], [blind_neg])
        commit1 = Secp256k1zkp::Pedersen::Commitment.generate(ctx, 101, blind_pos)
        commit2 = Secp256k1zkp::Pedersen::Commitment.generate(ctx, 75, blind_neg)
        commit3 = Secp256k1zkp::Pedersen::Commitment.generate(ctx, 26, blind_sum)

        expect(Secp256k1zkp::Pedersen::Commitment.valid_commit_sum?(ctx, [commit1], [commit2, commit3])).to be true
      end
    end
  end

  describe 'Commitment#blind_switch' do
    it do
      pos_value = 101
      neg_value = 75
      blind_pos = Secp256k1zkp::Pedersen::Commitment.blind_switch(ctx, pos_value, SecureRandom.hex(32).to_i(16))
      blind_neg = Secp256k1zkp::Pedersen::Commitment.blind_switch(ctx, neg_value, SecureRandom.hex(32).to_i(16))
      blind_sum = Secp256k1zkp::Pedersen::Commitment.blind_sum(ctx, [blind_pos], [blind_neg])
      diff = pos_value - neg_value
      commit1 = Secp256k1zkp::Pedersen::Commitment.generate(ctx, pos_value, blind_pos)
      commit2 = Secp256k1zkp::Pedersen::Commitment.generate(ctx, neg_value, blind_neg)
      commit3 = Secp256k1zkp::Pedersen::Commitment.generate(ctx, diff, blind_sum)
      expect(Secp256k1zkp::Pedersen::Commitment.valid_commit_sum?(ctx, [commit1], [commit2, commit3])).to be true
    end
  end

  describe 'Commitment#to_public_key' do
    it 'should convert to public key' do
      blind = SecureRandom.hex(32).to_i(16)
      commit = Secp256k1zkp::Pedersen::Commitment.generate(ctx, 5, blind)
      expect { commit.to_public_key(ctx) }.not_to raise_error
    end
  end
end
