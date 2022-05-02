# frozen_string_literal: true

require 'spec_helper'

RSpec.describe TapyrusZkp::Pedersen do

  let(:ctx) { TapyrusZkp::Context.new(caps: TapyrusZkp::SECP256K1_CONTEXT_COMMIT) }

  describe 'Commitment#from_hex and #to_hex' do
    it do
      hex_commitment = '09c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5'
      commit = TapyrusZkp::Pedersen::Commitment.from_hex(ctx, hex_commitment)
      expect(commit.to_hex(ctx)).to eq(hex_commitment)
    end

    context 'Invalid commitment' do
      it 'should raise error' do
        hex_commitment = '9c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5'
        expect { TapyrusZkp::Pedersen::Commitment.from_hex(ctx, hex_commitment) }.to raise_error(TapyrusZkp::InvalidCommit)
      end
    end
  end

  describe 'Commitment#generate' do
    it 'should generate commitment' do
      value = 1
      blind1 = generate_scalar
      blind2 = 1
      commit1 = TapyrusZkp::Pedersen::Commitment.generate(ctx, value, blind1)
      commit2 = TapyrusZkp::Pedersen::Commitment.generate(ctx, blind2, blind1)
      expect(commit1).to eq(commit2)
      value = 2
      commit1 = TapyrusZkp::Pedersen::Commitment.generate(ctx, value, blind1)
      commit2 = TapyrusZkp::Pedersen::Commitment.generate(ctx, blind2, blind1)
      expect(commit1).not_to eq(commit2)
    end
  end

  describe 'Commitment#blind_sum' do
    it 'should generate sum of blind commitment' do
      blind_a = generate_scalar
      blind_b = generate_scalar

      commit_a = TapyrusZkp::Pedersen::Commitment.generate(ctx, 3, blind_a)
      commit_b = TapyrusZkp::Pedersen::Commitment.generate(ctx, 2, blind_b)
      blind_c = TapyrusZkp::Pedersen::Commitment.blind_sum(ctx, [blind_a, blind_b], [])
      commit_c = TapyrusZkp::Pedersen::Commitment.generate(ctx, 3 + 2, blind_c)
      commit_d = TapyrusZkp::Pedersen::Commitment.commit_sum(ctx, [commit_a, commit_b], [])
      expect(commit_c).to eq(commit_d)

      blind_e = TapyrusZkp::Pedersen::Commitment.blind_sum(ctx, [blind_a], [blind_b])
      commit_e = TapyrusZkp::Pedersen::Commitment.generate(ctx, 3 - 2, blind_e)
      commit_f = TapyrusZkp::Pedersen::Commitment.commit_sum(ctx, [commit_a], [commit_b])
      expect(commit_e).to eq(commit_f)
    end
  end

  describe 'Commitment#valid_commit_sum?' do
    context 'one key' do
      it do
        commit1 = TapyrusZkp::Pedersen::Commitment.generate(ctx, 5, 1)
        commit2 = TapyrusZkp::Pedersen::Commitment.generate(ctx, 5, 1)
        expect(TapyrusZkp::Pedersen::Commitment.valid_commit_sum?(ctx, [commit1], [commit2])).to be true

        commit1 = TapyrusZkp::Pedersen::Commitment.generate(ctx, 3, 1)
        commit2 = TapyrusZkp::Pedersen::Commitment.generate(ctx, 2, 1)
        commit3 = TapyrusZkp::Pedersen::Commitment.generate(ctx, 5, 1)
        expect(TapyrusZkp::Pedersen::Commitment.valid_commit_sum?(ctx, [commit1, commit2], [commit3])).to be false

        two_key = TapyrusZkp::Pedersen::Commitment.blind_sum(ctx, [1, 1], [])
        commit3 = TapyrusZkp::Pedersen::Commitment.generate(ctx, 5, two_key)
        expect(TapyrusZkp::Pedersen::Commitment.valid_commit_sum?(ctx, [commit1, commit2], [commit3])).to be true
      end
    end

    context 'zero key' do
      it do
        commit1 = TapyrusZkp::Pedersen::Commitment.generate(ctx, 5, 0)
        commit2 = TapyrusZkp::Pedersen::Commitment.generate(ctx, 5, 0)
        expect(TapyrusZkp::Pedersen::Commitment.valid_commit_sum?(ctx, [commit1], [commit2])).to be true
        commit1 = TapyrusZkp::Pedersen::Commitment.generate(ctx, 3, 0)
        commit2 = TapyrusZkp::Pedersen::Commitment.generate(ctx, 2, 0)
        commit3 = TapyrusZkp::Pedersen::Commitment.generate(ctx, 5, 0)
        expect(TapyrusZkp::Pedersen::Commitment.valid_commit_sum?(ctx, [commit1, commit2], [commit3])).to be true
        commit1 = TapyrusZkp::Pedersen::Commitment.generate(ctx, 2, 0)
        commit2 = TapyrusZkp::Pedersen::Commitment.generate(ctx, 4, 0)
        commit3 = TapyrusZkp::Pedersen::Commitment.generate(ctx, 1, 0)
        commit4 = TapyrusZkp::Pedersen::Commitment.generate(ctx, 5, 0)
        expect(TapyrusZkp::Pedersen::Commitment.valid_commit_sum?(ctx, [commit1, commit2], [commit3, commit4])).to be true
      end
    end

    context 'random key' do
      it do
        blind_pos = generate_scalar
        blind_neg = generate_scalar
        blind_sum = TapyrusZkp::Pedersen::Commitment.blind_sum(ctx, [blind_pos], [blind_neg])
        commit1 = TapyrusZkp::Pedersen::Commitment.generate(ctx, 101, blind_pos)
        commit2 = TapyrusZkp::Pedersen::Commitment.generate(ctx, 75, blind_neg)
        commit3 = TapyrusZkp::Pedersen::Commitment.generate(ctx, 26, blind_sum)

        expect(TapyrusZkp::Pedersen::Commitment.valid_commit_sum?(ctx, [commit1], [commit2, commit3])).to be true
      end
    end
  end

  describe 'Commitment#blind_switch' do
    it do
      pos_value = 101
      neg_value = 75
      blind_pos = TapyrusZkp::Pedersen::Commitment.blind_switch(ctx, pos_value, generate_scalar)
      blind_neg = TapyrusZkp::Pedersen::Commitment.blind_switch(ctx, neg_value, generate_scalar)
      blind_sum = TapyrusZkp::Pedersen::Commitment.blind_sum(ctx, [blind_pos], [blind_neg])
      diff = pos_value - neg_value
      commit1 = TapyrusZkp::Pedersen::Commitment.generate(ctx, pos_value, blind_pos)
      commit2 = TapyrusZkp::Pedersen::Commitment.generate(ctx, neg_value, blind_neg)
      commit3 = TapyrusZkp::Pedersen::Commitment.generate(ctx, diff, blind_sum)
      expect(TapyrusZkp::Pedersen::Commitment.valid_commit_sum?(ctx, [commit1], [commit2, commit3])).to be true
    end
  end

  describe 'Commitment#to_public_key and from_public_key' do
    it do
      blind = generate_scalar
      commit = TapyrusZkp::Pedersen::Commitment.generate(ctx, 5, blind)
      public_key = commit.to_public_key(ctx)
      expect(TapyrusZkp::Pedersen::Commitment.from_public_key(ctx, public_key)).to eq(commit)
      new_commit = TapyrusZkp::Pedersen::Commitment.from_public_key(ctx, public_key)
      expect(new_commit).to eq(commit)
    end
  end

  describe 'sign with public key from commitment' do
    it do
      blind = TapyrusZkp::PrivateKey.generate(ctx)
      commit = TapyrusZkp::Pedersen::Commitment.generate(ctx, 0, blind.to_i)
      msg = SecureRandom.bytes(32)
      sig = blind.sign(ctx, msg)
      public_key = commit.to_public_key(ctx)
      expect(public_key.valid_sig?(ctx, msg, sig)).to be true
    end
  end
end
