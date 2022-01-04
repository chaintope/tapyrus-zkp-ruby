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
    end
  end

end
