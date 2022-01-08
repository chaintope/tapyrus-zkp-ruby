# frozen_string_literal: true

module Secp256k1zkp

  # Secp256k1 public key
  class PublicKey < FFI::Struct
    layout :data, [:uchar, 64]

    # Generate public key from hex string.
    # @param [Secp256k1zkp::Context] ctx Secp256k1 context.
    # @param [String] pubkey_hex Public key hex string.
    # @return [Secp256k1zkp::PublicKey] Public key object.
    # @raise [Secp256k1zkp::InvalidPublicKey]
    def self.from_hex(ctx, pubkey_hex)
      raw_pubkey = [pubkey_hex].pack('H*')
      raise InvalidPublicKey, 'Invalid public key size.' unless [33, 65].include?(raw_pubkey.bytesize)

      data = FFI::MemoryPointer.new(:uchar, raw_pubkey.bytesize).put_bytes(0, raw_pubkey)

      pubkey = PublicKey.new
      res = C.secp256k1_ec_pubkey_parse(ctx.ctx, pubkey.pointer, data, data.size)
      raise InvalidPublicKey unless res == 1

      pubkey
    end

    # Generate public key from private key.
    # @param [Secp256k1zkp::Context] ctx Secp256k1 context.
    # @param [String] private_key_hex Private key hex string.
    # @return [Secp256k1zkp::PublicKey] Public key object.
    # @raise [Secp256k1zkp::AssertError]
    def self.from_private_key(ctx, private_key_hex)
      raw_priv_key = [private_key_hex].pack('H*')
      priv = FFI::MemoryPointer.new(:uchar, raw_priv_key.bytesize).put_bytes(0, raw_priv_key)
      pubkey = PublicKey.new
      res = C.secp256k1_ec_pubkey_create(ctx, pubkey.pointer, priv)
      raise AssertError, 'failed to generate public key' unless res == 1

      pubkey
    end

    # Generate public key hex string.
    # @param [Secp256k1zkp::Context] ctx Secp256k1 context.
    # @param [Boolean] compressed whether compressed public key or not.
    # @return [String] Public key hex string.
    # @raise [Secp256k1zkp::AssertError]
    def to_hex(ctx, compressed: true)
      len_compressed = compressed ? 33 : 65
      output = FFI::MemoryPointer.new(:uchar, len_compressed)
      out_len = FFI::MemoryPointer.new(:size_t).write_uint(len_compressed)
      compress_flag = compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED
      res = C.secp256k1_ec_pubkey_serialize(ctx.ctx, output, out_len, self.pointer, compress_flag)
      raise AssertError, 'Pubkey serialization failed' unless res == 1

      output.read_bytes(len_compressed).unpack1('H*')
    end

    # Verify signature.
    # @param [Secp256k1zkp::Context] ctx Secp256k1 context.
    # @param [String] msg signed message with binary format.
    # @param [Secp256k1zkp::ECDSA::Signature] sig signature.
    # @return [Boolean]
    def valid_sig?(ctx, msg, sig)
      msg_ptr = FFI::MemoryPointer.new(:uchar, msg.bytesize).put_bytes(0, msg)
      res = C.secp256k1_ecdsa_verify(ctx.ctx, sig.pointer, msg_ptr, pointer)
      res == 1
    end

    # Generate shared secret from +private_key+ and self.
    # @param [Secp256k1zkp::Context] ctx Secp256k1 context.
    # @param [Secp256k1zkp::PrivateKey] private_key
    # @return [Secp256k1zkp::ECDH::SharedSecret]
    def ecdh(ctx, private_key)
      ECDH.generate(ctx, self, private_key)
    end

    # Override +==+ to check whether same public key or not.
    # @param [Secp256k1zkp::PublicKey] other
    # @return [Boolean]
    def ==(other)
      return false unless other.is_a?(PublicKey)

      self[:data].to_a == other[:data].to_a
    end
  end

  # Secp256k1 private key
  class PrivateKey

    BYTE_SIZE = 32

    attr_reader :key

    # @param [Secp256k1zkp::Context] ctx Secp256k1 context.
    # @param [String] key private key with binary format.
    # @return [Secp256k1zkp::PrivateKey]
    # @raise [Secp256k1zkp::InvalidPrivateKey]
    def initialize(ctx, key)
      raise InvalidPrivateKey, 'Invalid private key size' unless key.bytesize == BYTE_SIZE

      priv_ptr = FFI::MemoryPointer.new(:uchar, BYTE_SIZE).put_bytes(0, key)
      res = C.secp256k1_ec_seckey_verify(ctx.ctx, priv_ptr)
      raise InvalidPrivateKey unless res == 1

      @key = key
    end

    # Generate private key.
    # @param [Secp256k1zkp::Context] ctx Secp256k1 context.
    # @return [Secp256k1zkp::PrivateKey]
    def self.generate(ctx)
      from_hex(ctx, SecureRandom.hex(BYTE_SIZE))
    rescue InvalidPrivateKey
      generate(ctx)
    end

    # Generate key pair.
    # @param [Secp256k1zkp::Context] ctx Secp256k1 context.
    # @return [Array(Secp256k1zkp::PrivateKey, Secp256k1zkp::PublicKey)]
    def self.generate_keypair(ctx)
      private_key = generate(ctx)
      [private_key, private_key.public_key(ctx)]
    end

    # Initialize private key from hex data.
    # @param [Secp256k1zkp::Context] ctx Secp256k1 context.
    # @param [String] key private key with hex format.
    # @return [Secp256k1zkp::PrivateKey]
    def self.from_hex(ctx, privkey_hex)
      raw_priv = [privkey_hex].pack('H*')
      PrivateKey.new(ctx, raw_priv)
    end

    # Calculate public key
    # @param [Secp256k1zkp::Context] ctx Secp256k1 context.
    # @return [Secp256k1zkp::PublicKey]
    # @raise [Secp256k1zkp::AssertError]
    def public_key(ctx)
      public_key = PublicKey.new
      res = C.secp256k1_ec_pubkey_create(ctx.ctx, public_key.pointer, pointer)
      raise AssertError, 'secp256k1_ec_pubkey_create failed' unless res == 1

      public_key
    end

    # Generate signature.
    # @param [Secp256k1zkp::Context] ctx Secp256k1 context.
    # @param [String] msg message with binary format to be signed.
    # @return [Secp256k1zkp::ECDSA::Signature]
    # @raise [Secp256k1zkp::AssertError]
    def sign(ctx, msg)
      msg_ptr = FFI::MemoryPointer.new(:uchar, msg.bytesize).put_bytes(0, msg)
      signature = Secp256k1zkp::ECDSA::Signature.new
      res = C.secp256k1_ecdsa_sign(ctx.ctx, signature.pointer, msg_ptr, pointer, nil, nil)
      raise AssertError, 'secp256k1_ecdsa_sign failed' unless res == 1

      signature
    end

    # Generate recoverable signature.
    # Note: This method can only be used if the libsecp256k1-zkp recovery module is enabled.
    # @param [Secp256k1zkp::Context] ctx Secp256k1 context.
    # @param [String] msg message with binary format to be signed.
    # @return [Secp256k1zkp::ECDSA::RecoverableSignature]
    # @raise [Secp256k1zkp::AssertError]
    def sign_recoverable(ctx, msg)
      msg_ptr = FFI::MemoryPointer.new(:uchar, msg.bytesize).put_bytes(0, msg)
      signature = Secp256k1zkp::ECDSA::RecoverableSignature.new
      res = C.secp256k1_ecdsa_sign_recoverable(ctx.ctx, signature.pointer, msg_ptr, pointer, nil, nil)
      raise AssertError, 'secp256k1_ecdsa_sign_recoverable failed' unless res == 1

      signature
    end

    # Generate shared secret from +public_key+ and self.
    # @param [Secp256k1zkp::Context] ctx Secp256k1 context.
    # @param [Secp256k1zkp::PublicKey] public_key
    # @return [Secp256k1zkp::ECDH::SharedSecret]
    def ecdh(ctx, public_key)
      ECDH.generate(ctx, public_key, self)
    end

    def pointer
      FFI::MemoryPointer.new(:uchar, BYTE_SIZE).put_bytes(0, key)
    end
  end

end
