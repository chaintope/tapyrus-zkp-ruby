# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Secp256k1zkp::Bulletproof do

  let(:ctx) { Secp256k1zkp::Context.new(caps: Secp256k1zkp::SECP256K1_CONTEXT_COMMIT) }

  describe 'single bulletproof' do
    it do
      blind = generate_scalar
      value = 12_345_678
      commit = Secp256k1zkp::Pedersen::Commitment.generate(ctx, value, blind)
      bullet_proof = Secp256k1zkp::Bulletproof.generate(ctx, value, blind, blind, blind)
      expect(Secp256k1zkp::Bulletproof.valid_bullet_proof?(ctx, commit, bullet_proof)).to be true
    end
  end

end
