# frozen_string_literal: true

module TapyrusZkp

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
    # @param [TapyrusZkp::Context] ctx Secp256k1 context.
    # @param [TapyrusZkp::PublicKey] public_key public key.
    # @param [TapyrusZkp::PrivateKey] private_key private key.
    # @return [TapyrusZkp::SharedSecret]
    def generate(ctx, public_key, private_key)
      secret = SharedSecret.new
      res = C.secp256k1_ecdh(ctx.ctx, secret.pointer, public_key.pointer, private_key.pointer)
      raise AssertError, 'secp256k1_ecdh failed' unless res == 1

      secret
    end

  end
end
