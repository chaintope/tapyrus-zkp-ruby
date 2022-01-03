# frozen_string_literal: true

module Secp256k1zkp

  # Secp256k1 public key
  class PublicKey < FFI::Struct
    layout :data, [:uchar, 64]

    # Generate public key from hex string.
    # @param [Secp256k1zkp::Context] ctx Secp256k1 context.
    # @param [String] pubkey_hex Public key hex string.
    # @return [Secp256k1zkp::PublicKey] Public key object.
    def self.from_hex(ctx, pubkey_hex)
      raw_pubkey = [pubkey_hex].pack('H*')
      raise InvalidPublicKey, 'Invalid public key size.' unless [33, 65].include?(raw_pubkey.bytesize)

      data = FFI::MemoryPointer.new(:uchar, raw_pubkey.bytesize).put_bytes(0, raw_pubkey)

      pubkey = PublicKey.new
      res = C.secp256k1_ec_pubkey_parse(ctx.ctx, pubkey.pointer, data, data.size)
      raise InvalidPublicKey unless res == 1

      pubkey
    end

    # Generate public key hex string.
    # @param [Secp256k1zkp::Context] ctx Secp256k1 context.
    # @param [Boolean] compressed whether compressed public key or not.
    # @return [String] Public key hex string.
    def to_hex(ctx, compressed: true)
      len_compressed = compressed ? 33 : 65
      output = FFI::MemoryPointer.new(:uchar, len_compressed)
      out_len = FFI::MemoryPointer.new(:size_t).write_uint(len_compressed)
      compress_flag = compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED
      res = C.secp256k1_ec_pubkey_serialize(ctx.ctx, output, out_len, self.pointer, compress_flag)
      raise Error, 'Pubkey serialization failed' unless res == 1

      output.read_bytes(len_compressed).unpack1('H*')
    end
  end

end
