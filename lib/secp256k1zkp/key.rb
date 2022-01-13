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

    # Add a number of public keys together.
    # @param [Secp256k1zkp::Context] ctx Secp256k1 context.
    # @param [Array(Secp256k1zkp::PublicKey)] public_keys public keys to be added.
    # @return [Secp256k1zkp::PublicKey]
    # @raise [InvalidPublicKey]
    def self.from_combination(ctx, *public_keys)
      public_key = PublicKey.new
      pubkeys_ptr = FFI::MemoryPointer.new(:pointer, public_keys.length)
      public_keys.each_with_index do |key, i|
        pubkeys_ptr[i].put_pointer(0, key.pointer)
      end
      res = C.secp256k1_ec_pubkey_combine(ctx.ctx, public_key.pointer, pubkeys_ptr, public_keys.length)
      raise InvalidPublicKey unless res == 1

      public_key
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
      raise ArgumentError, 'sig must be Secp256k1zkp::ECDSA::Signature instance' unless sig.is_a?(Secp256k1zkp::ECDSA::Signature)

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

    # Tweak a public key by adding tweak times the generator to it. (P + tG)
    # @param [Secp256k1zkp::Context] ctx Secp256k1 context.
    # @param [Integer] scalar
    # @raise [ArgumentError]
    # @raise [IncapableContext]
    def tweak_add!(ctx, scalar)
      raise ArgumentError unless scalar.is_a?(Integer)
      raise IncapableContext if ctx.caps?(SECP256K1_CONTEXT_SIGN) || ctx.caps?(SECP256K1_CONTEXT_NONE)

      tweak = FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, [scalar.to_even_hex(32)].pack('H*'))
      res = C.secp256k1_ec_pubkey_tweak_add(ctx.ctx, pointer, tweak)
      raise InvalidPrivateKey unless res == 1
    end

    # Tweak a public key by multiplying it by a +scalar+ value. (tP)
    # @param [Secp256k1zkp::Context] ctx Secp256k1 context.
    # @param [Integer] scalar tweak value.
    # @raise [ArgumentError]
    # @raise [Secp256k1zkp::IncapableContext]
    def tweak_mul!(ctx, scalar)
      raise ArgumentError unless scalar.is_a?(Integer)
      raise IncapableContext if ctx.caps?(SECP256K1_CONTEXT_SIGN) || ctx.caps?(SECP256K1_CONTEXT_NONE)

      tweak = FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, [scalar.to_even_hex(32)].pack('H*'))
      res = C.secp256k1_ec_pubkey_tweak_mul(ctx.ctx, pointer, tweak)
      raise AssertError, 'secp256k1_ec_pubkey_tweak_mul failed' unless res == 1
    end

    # Negates a public key in place.
    # @param [Secp256k1zkp::Context] ctx Secp256k1 context.
    def negate!(ctx)
      res = C.secp256k1_ec_pubkey_negate(ctx.ctx, pointer)
      raise AssertError, 'secp256k1_ec_pubkey_negate failed' unless res == 1
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
    # @raise [Secp256k1zkp::InvalidPrivateKey]
    def self.from_hex(ctx, privkey_hex)
      raw_priv = [privkey_hex].pack('H*')
      raise InvalidPrivateKey, 'private key should be 32 bytes' unless raw_priv.unpack1('H*') == privkey_hex

      PrivateKey.new(ctx, raw_priv)
    end

    # Calculate public key
    # @param [Secp256k1zkp::Context] ctx Secp256k1 context.
    # @return [Secp256k1zkp::PublicKey]
    # @raise [Secp256k1zkp::AssertError]
    # @raise [Secp256k1zkp::IncapableContext]
    def public_key(ctx)
      raise IncapableContext if ctx.caps?(SECP256K1_CONTEXT_VERIFY) || ctx.caps?(SECP256K1_CONTEXT_NONE)

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

    # Override +==+ to check whether same private key or not.
    # @param [Secp256k1zkp::PublicKey] other
    # @return [Boolean]
    def ==(other)
      return false unless other.is_a?(PrivateKey)

      to_hex == other.to_hex
    end

    # Convert private key to hex.
    # @return [String]
    def to_hex
      key.unpack1('H*')
    end

    # Convert private key to integer.
    # @return [Integer]
    def to_i
      to_hex.to_i(16)
    end

    # Tweak a private key by adding tweak to it.
    # @param [Secp256k1zkp::Context] ctx Secp256k1 context.
    # @param [Integer] scalar tweak value.
    # @raise [ArgumentError]
    # @raise [AssertError]
    def tweak_add!(ctx, scalar)
      raise ArgumentError unless scalar.is_a?(Integer)

      process_with_update do |pointer|
        tweak = FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, [scalar.to_even_hex(32)].pack('H*'))
        res = C.secp256k1_ec_privkey_tweak_add(ctx.ctx, pointer, tweak)
        raise AssertError, 'secp256k1_ec_privkey_tweak_add failed' unless res == 1
      end
    end

    # Tweak a private key by multiplying it by a +scalar+.
    # @param [Secp256k1zkp::Context] ctx Secp256k1 context.
    # @param [Integer] scalar tweak value.
    # @raise [ArgumentError]
    # @raise [Secp256k1zkp::IncapableContext]
    def tweak_mul!(ctx, scalar)
      raise ArgumentError unless scalar.is_a?(Integer)

      process_with_update do |pointer|
        tweak = FFI::MemoryPointer.new(:uchar, 32).put_bytes(0, [scalar.to_even_hex(32)].pack('H*'))
        res = C.secp256k1_ec_privkey_tweak_mul(ctx.ctx, pointer, tweak)
        raise AssertError, 'secp256k1_ec_privkey_tweak_mul failed' unless res == 1
      end
    end

    # Negates a private key in place.
    # @param [Secp256k1zkp::Context] ctx Secp256k1 context.
    def negate!(ctx)
      process_with_update do |pointer|
        res = C.secp256k1_ec_privkey_tweak_neg(ctx.ctx, pointer)
        raise AssertError, 'secp256k1_ec_privkey_tweak_neg failed' unless res == 1
      end
    end

    # Tweak a private key by inverting it.
    # @param [Secp256k1zkp::Context] ctx Secp256k1 context.
    def inv!(ctx)
      process_with_update do |pointer|
        res = C.secp256k1_ec_privkey_tweak_inv(ctx.ctx, pointer)
        raise AssertError, 'secp256k1_ec_privkey_tweak_inv failed' unless res == 1
      end
    end

    private

    def process_with_update
      priv_ptr = pointer
      yield(priv_ptr)
      @key = priv_ptr.read_bytes(BYTE_SIZE)
    end
  end

end
