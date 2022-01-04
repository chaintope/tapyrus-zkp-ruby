# frozen_string_literal: true

require 'securerandom'

module Secp256k1zkp

  # All flags' lower 8 bits indicate what they're for. Do not use directly.
  SECP256K1_FLAGS_TYPE_MASK = ((1 << 8) - 1)
  SECP256K1_FLAGS_TYPE_CONTEXT = (1 << 0)
  SECP256K1_FLAGS_TYPE_COMPRESSION = (1 << 1)
  # The higher bits contain the actual data. Do not use directly.
  SECP256K1_FLAGS_BIT_CONTEXT_VERIFY = (1 << 8)
  SECP256K1_FLAGS_BIT_CONTEXT_SIGN = (1 << 9)
  SECP256K1_FLAGS_BIT_COMPRESSION = (1 << 8)

  # Flag to pass to secp256k1_ec_pubkey_serialize and secp256k1_ec_privkey_export.
  SECP256K1_EC_COMPRESSED = (SECP256K1_FLAGS_TYPE_COMPRESSION | SECP256K1_FLAGS_BIT_COMPRESSION)
  SECP256K1_EC_UNCOMPRESSED = SECP256K1_FLAGS_TYPE_COMPRESSION

  # Flags to pass to secp256k1_context_create, secp256k1_context_preallocated_size, and
  # secp256k1_context_preallocated_create.
  SECP256K1_CONTEXT_VERIFY = (SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_VERIFY)
  SECP256K1_CONTEXT_SIGN = (SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_SIGN)
  SECP256K1_CONTEXT_NONE = SECP256K1_FLAGS_TYPE_CONTEXT
  SECP256K1_CONTEXT_FULL = (SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)

  # FFI bindings
  module C
    extend FFI::Library

    ffi_lib(ENV['LIBSECP256K1-ZKP'] || 'libsecp256k1')

    module_function

    # secp256k1_context* secp256k1_context_create(unsigned int flags)
    attach_function :secp256k1_context_create, [:uint], :pointer
    # void secp256k1_context_destroy(secp256k1_context* ctx)
    attach_function :secp256k1_context_destroy, [:pointer], :void
    # int secp256k1_context_randomize(secp256k1_context* ctx, const unsigned char *seed32)
    attach_function :secp256k1_context_randomize, [:pointer, :pointer], :int
    # int secp256k1_ec_pubkey_parse(const secp256k1_context* ctx, secp256k1_pubkey* pubkey, const unsigned char *input, size_t inputlen)
    attach_function :secp256k1_ec_pubkey_parse, [:pointer, :pointer, :pointer, :size_t], :int
    # int secp256k1_ec_pubkey_serialize(const secp256k1_context* ctx, unsigned char *output, size_t *outputlen, const secp256k1_pubkey *pubkey, unsigned int flags)
    attach_function :secp256k1_ec_pubkey_serialize, [:pointer, :pointer, :pointer, :pointer, :uint], :int
    # int secp256k1_ec_pubkey_create(const secp256k1_context* ctx, secp256k1_pubkey *pubkey, const unsigned char *seckey)
    attach_function :secp256k1_ec_pubkey_create, [:pointer, :pointer, :pointer], :int
    # int secp256k1_ec_seckey_verify(const secp256k1_context* ctx, const unsigned char *seckey)
    attach_function :secp256k1_ec_seckey_verify, [:pointer, :pointer], :int

  end
end
