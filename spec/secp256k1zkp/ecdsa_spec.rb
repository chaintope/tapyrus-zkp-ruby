# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Secp256k1zkp::ECDSA do

  let(:ctx) { Secp256k1zkp::Context.new }

  describe 'Signature#from_der' do
    context 'Invalid signature' do
      it 'should raise InvalidSignature' do
        sig = hex!('00' * Secp256k1zkp::ECDSA::Signature::SIZE_SERIALIZED)
        expect { Secp256k1zkp::ECDSA::Signature.from_der(ctx, sig) }.to raise_error(Secp256k1zkp::InvalidSignature)
        sig = hex!('00' * (Secp256k1zkp::ECDSA::Signature::SIZE_SERIALIZED + 1))
        expect { Secp256k1zkp::ECDSA::Signature.from_der(ctx, sig) }.to raise_error(Secp256k1zkp::InvalidSignature)
      end
    end
  end

  describe 'signature serialization round trip' do
    it 'should success' do
      100.times do
        msg = SecureRandom.bytes(Secp256k1zkp::PrivateKey::BYTE_SIZE)
        private_key = Secp256k1zkp::PrivateKey.generate(ctx)
        sig1 = private_key.sign(ctx, msg)

        # DER
        der = sig1.to_der(ctx)
        sig2 = Secp256k1zkp::ECDSA::Signature.from_der(ctx, der)
        expect(sig1).to eq(sig2)

        # Compact
        compact = sig1.to_compact(ctx)
        sig2 = Secp256k1zkp::ECDSA::Signature.from_compact(ctx, compact)
        expect(sig1).to eq(sig2)
      end
    end
  end

end
