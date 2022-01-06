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

        expect { Secp256k1zkp::ECDSA::Signature.from_der(ctx, compact) }.to raise_error(Secp256k1zkp::InvalidSignature)
        expect { Secp256k1zkp::ECDSA::Signature.from_compact(ctx, der) }.to raise_error(Secp256k1zkp::InvalidSignature)
      end
    end
  end

  describe 'LOW-S signature' do
    it do
      sig = hex!('3046022100839c1fbc5304de944f697c9f4b1d01d1faeba32d751c0f7acb21ac8a0f436a72022100e89bd46bb3a5a62adc679f659b7ce876d83ee297c7a5587b2011c4fcc72eab45')
      msg = hex!('a4965ca63b7d8562736ceec36dfa5a11bf426eb65be8ea3f7a49ae363032da0d')

      signature = Secp256k1zkp::ECDSA::Signature.from_der(ctx, sig)
      pubkey = Secp256k1zkp::PublicKey.from_hex(ctx, '031ee99d2b786ab3b0991325f2de8489246a6a3fdb700f6d0511b1d80cf5f4cd43')

      # without normalization we expect this will fail
      expect(pubkey.valid_sig?(ctx, msg, signature)).to be false
      # after normalization it should pass
      signature.normalize_s!(ctx)
      expect(pubkey.valid_sig?(ctx, msg, signature)).to be true
    end
  end

  describe 'Recoverable signature' do
    it do
      one = '0000000000000000000000000000000000000000000000000000000000000001'
      private_key = Secp256k1zkp::PrivateKey.from_hex(ctx, one)
      msg = hex!(one)
      sig1 = private_key.sign_recoverable(ctx, msg)
      compact = hex!('6673ffad2147741f04772b6f921f0ba6af0c1e77fc439e65c36dedf4092e88984c1a971652e0ada880120ef8025e709fff2080c4a39aae068d12eed009b68c89')
      sig2 = Secp256k1zkp::ECDSA::RecoverableSignature.from_compact(ctx, compact, 1)
      expect(sig1).to eq(sig2)
      expect(sig2.to_compact(ctx)).to eq([1, compact])

      sig = sig1.to_standard(ctx)
      public_key = private_key.public_key(ctx)
      expect(public_key.valid_sig?(ctx, msg, sig)).to be true
      msg2 = hex!('0000000000000000000000000000000000000000000000000000000000000002')
      expect(public_key.valid_sig?(ctx, msg2, sig)).to be false

      expect(sig1.recover(ctx, msg)).to eq(public_key)
    end
  end
end
