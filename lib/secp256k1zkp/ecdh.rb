# frozen_string_literal: true

module Secp256k1zkp

  # ECDH module
  # Note: This module can only be used if the libsecp256k1-zkp ecdh module is enabled.
  module ECDH

    # Shared secret.
    class SharedSecret < FFI::Struct
      layout :data, [:uchar, 32]

      def ==(other)
        return false unless other.is_a?(SharedSecret)

        self[:data].to_a == other[:data].to_a
      end
    end

    module_function

    # Gene a new shared secret from a public key and private key
    # @param [Secp256k1zkp::Context] ctx Secp256k1 context.
    # @param [Secp256k1zkp::PublicKey] public_key public key.
    # @param [Secp256k1zkp::PrivateKey] private_key private key.
    # @return [Secp256k1zkp::SharedSecret]
    def generate(ctx, public_key, private_key)
      secret = SharedSecret.new
      res = C.secp256k1_ecdh(ctx.ctx, secret.pointer, public_key.pointer, private_key.pointer)
      raise AssertError, 'secp256k1_ecdh failed' unless res == 1

      secret
    end

  end
end
