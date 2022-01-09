# frozen_string_literal: true

require 'spec_helper'

RSpec.describe 'Key' do

  let(:ctx) { Secp256k1zkp::Context.new }

  describe 'PublicKey#from_hex' do
    context 'Invalid public key' do
      it 'raise InvalidPublicKey error' do
        expect { Secp256k1zkp::PublicKey.from_hex(ctx, nil) }.to raise_error(Secp256k1zkp::InvalidPublicKey)
        expect { Secp256k1zkp::PublicKey.from_hex(ctx, '1') }.to raise_error(Secp256k1zkp::InvalidPublicKey)
      end
    end

    context 'Valid public key' do
      it 'should parse public key' do
        uncompressed = '04363995efa294aff6feef4b9a980a52eae055dc286439791ea25e9c87434a31b339ec35a27c9590a84d4a1e48d3e56e6f3760c156e3b798c39b33f77b713ce4bc'
        uncompressed_key = Secp256k1zkp::PublicKey.from_hex(ctx, uncompressed)
        expect(uncompressed_key.to_hex(ctx, compressed: false)).to eq(uncompressed)
        compressed = '0317b7e1ce1f9f94c32a43739229f88c0b0333296fb46e8f72865849c6ae34b84e'
        compressed_key = Secp256k1zkp::PublicKey.from_hex(ctx, compressed)
        expect(compressed_key.to_hex(ctx)).to eq(compressed)
      end
    end
  end

  describe 'PrivateKey#initialize' do
    context 'Invalid private key' do
      it 'should raise InvalidPrivateKey' do
        expect { Secp256k1zkp::PrivateKey.from_hex(ctx, 'ff' * 32) }.to raise_error(Secp256k1zkp::InvalidPrivateKey)
        expect { Secp256k1zkp::PrivateKey.from_hex(ctx, '00' * 32) }.to raise_error(Secp256k1zkp::InvalidPrivateKey)
        expect { Secp256k1zkp::PrivateKey.from_hex(ctx, nil) }.to raise_error(Secp256k1zkp::InvalidPrivateKey)
        # over max range
        key = 'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141'
        expect { Secp256k1zkp::PrivateKey.from_hex(ctx, key) }.to raise_error(Secp256k1zkp::InvalidPrivateKey)
      end
    end

    context 'Valid private key' do
      it 'should generate Secp256k1zkp::PrivateKey' do
        # max range
        key = 'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140'
        expect(Secp256k1zkp::PrivateKey.from_hex(ctx, key).key).to eq([key].pack('H*'))
      end
    end
  end

  describe 'PrivateKey#public_key' do
    it 'should return PublicKey' do
      private_key = Secp256k1zkp::PrivateKey.from_hex(ctx, '206f3acb5b7ac66dacf87910bb0b04bed78284b9b50c0d061705a44447a947ff')
      expect(private_key.public_key(ctx).to_hex(ctx)).to eq('020025aeb645b64b632c91d135683e227cb508ebb1766c65ee40405f53b8f1bb3a')
      # context sign
      expect { private_key.public_key(ctx_sign) }.not_to raise_error(Secp256k1zkp::IncapableContext)
    end

    context 'bad context' do
      it do
        private_key = Secp256k1zkp::PrivateKey.from_hex(ctx, '206f3acb5b7ac66dacf87910bb0b04bed78284b9b50c0d061705a44447a947ff')
        # context none
        expect { private_key.public_key(ctx_none) }.to raise_error(Secp256k1zkp::IncapableContext)
        # context verify
        expect { private_key.public_key(ctx_verify) }.to raise_error(Secp256k1zkp::IncapableContext)
      end
    end
  end

  describe 'PublicKey#tweak_mul!' do
    let(:key) { Secp256k1zkp::PublicKey.from_hex(ctx_none, '024175217e076deb6463831fce1ce271ef1f9e277e0dae071cb0039c38c50f19f2') }

    it 'should be tweaked' do
      scalar = 0x559359ae20f852dc89cad18cebdcae0b4abd06c5f014bcbca8a26cdd3dcdb6b1
      key.tweak_mul!(ctx_verify, scalar)
      expect(key.to_hex(ctx_verify)).to eq('02ff93dc38492c8d7405e3709e09f7e735b0bba85c62a87098d072b8c18cf75306')
    end

    context 'bad context' do
      it 'should raise Secp256k1zkp::IncapableContext' do
        expect { key.tweak_mul!(ctx_none, 1) }.to raise_error(Secp256k1zkp::IncapableContext)
        expect { key.tweak_mul!(ctx_sign, 1) }.to raise_error(Secp256k1zkp::IncapableContext)
      end
    end
  end

  describe 'PrivateKey#tweak_mul!' do
    let(:key) { Secp256k1zkp::PrivateKey.from_hex(ctx_none, 'c3f66d1051dfc546636b9f966a6f54932ea1db7087224e1b0e0d1a7eb756f7be') }

    it 'should be tweaked' do
      scalar = 0x559359ae20f852dc89cad18cebdcae0b4abd06c5f014bcbca8a26cdd3dcdb6b1
      key.tweak_mul!(ctx_none, scalar)
      expect(key.public_key(ctx).to_hex(ctx_verify)).to eq('02ff93dc38492c8d7405e3709e09f7e735b0bba85c62a87098d072b8c18cf75306')

      scalar = SecureRandom.hex(32).to_i(16)
      priv1, pub1 = Secp256k1zkp::PrivateKey.generate_keypair(ctx)
      priv1.tweak_mul!(ctx, scalar)
      pub1.tweak_mul!(ctx, scalar)
      expect(priv1.public_key(ctx)).to eq(pub1)
    end
  end
end
