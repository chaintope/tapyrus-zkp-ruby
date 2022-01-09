# frozen_string_literal: true

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

    # Contexts
    # secp256k1_context* secp256k1_context_create(unsigned int flags)
    attach_function :secp256k1_context_create, [:uint], :pointer
    # void secp256k1_context_destroy(secp256k1_context* ctx)
    attach_function :secp256k1_context_destroy, [:pointer], :void
    # int secp256k1_context_randomize(secp256k1_context* ctx, const unsigned char *seed32)
    attach_function :secp256k1_context_randomize, [:pointer, :pointer], :int

    # secp256k1_scratch_space_createconst secp256k1_context* ctx, size_t max_size)
    attach_function :secp256k1_scratch_space_create, [:pointer, :size_t], :pointer
    # void secp256k1_scratch_space_destroy(secp256k1_scratch_space* scratch)
    attach_function :secp256k1_scratch_space_destroy, [:pointer], :void

    # Pubkey
    # int secp256k1_ec_pubkey_parse(const secp256k1_context* ctx, secp256k1_pubkey* pubkey, const unsigned char *input, size_t inputlen)
    attach_function :secp256k1_ec_pubkey_parse, [:pointer, :pointer, :pointer, :size_t], :int
    # int secp256k1_ec_pubkey_serialize(const secp256k1_context* ctx, unsigned char *output, size_t *outputlen, const secp256k1_pubkey *pubkey, unsigned int flags)
    attach_function :secp256k1_ec_pubkey_serialize, [:pointer, :pointer, :pointer, :pointer, :uint], :int

    # EC key
    # int secp256k1_ec_pubkey_create(const secp256k1_context* ctx, secp256k1_pubkey *pubkey, const unsigned char *seckey)
    attach_function :secp256k1_ec_pubkey_create, [:pointer, :pointer, :pointer], :int
    # int secp256k1_ec_seckey_verify(const secp256k1_context* ctx, const unsigned char *seckey)
    attach_function :secp256k1_ec_seckey_verify, [:pointer, :pointer], :int

    # Signatures
    # int secp256k1_ecdsa_signature_parse_der(const secp256k1_context* ctx, secp256k1_ecdsa_signature* sig, const unsigned char *input, size_t inputlen)
    attach_function :secp256k1_ecdsa_signature_parse_der, [:pointer, :pointer, :pointer, :size_t], :int
    # int secp256k1_ecdsa_signature_parse_compact(const secp256k1_context* ctx, secp256k1_ecdsa_signature* sig, const unsigned char *input64)
    attach_function :secp256k1_ecdsa_signature_parse_compact, [:pointer, :pointer, :pointer], :int
    # int secp256k1_ecdsa_signature_serialize_der(const secp256k1_context* ctx, unsigned char *output, size_t *outputlen, const secp256k1_ecdsa_signature* sig)
    attach_function :secp256k1_ecdsa_signature_serialize_der, [:pointer, :pointer, :pointer, :pointer], :int
    # int secp256k1_ecdsa_signature_serialize_compact(const secp256k1_context* ctx, unsigned char *output64, const secp256k1_ecdsa_signature* sig)
    attach_function :secp256k1_ecdsa_signature_serialize_compact, [:pointer, :pointer, :pointer], :int
    # int secp256k1_ecdsa_signature_normalize(const secp256k1_context *ctx, const secp256k1_ecdsa_signature *sigout, const secp256k1_ecdsa_signature *sigin)
    attach_function :secp256k1_ecdsa_signature_normalize, [:pointer, :pointer, :pointer], :int

    # ECDSA
    # int secp256k1_ecdsa_sign(const secp256k1_context* ctx, secp256k1_ecdsa_signature *sig, const unsigned char *msg32, const unsigned char *seckey, secp256k1_nonce_function noncefp, const void *ndata)
    attach_function :secp256k1_ecdsa_sign, [:pointer, :pointer, :pointer, :pointer, :pointer, :pointer], :int
    # int secp256k1_ecdsa_verify(const secp256k1_context *ctx, const secp256k1_ecdsa_signature *sig, const unsigned char *msg32, const secp256k1_pubkey *pubkey)
    attach_function :secp256k1_ecdsa_verify, [:pointer, :pointer, :pointer, :pointer], :int

    # Tweak
    # int secp256k1_ec_pubkey_tweak_add(const secp256k1_context* ctx, secp256k1_pubkey *pubkey, const unsigned char *tweak)
    attach_function :secp256k1_ec_pubkey_tweak_add, [:pointer, :pointer, :pointer], :int
    # int secp256k1_ec_pubkey_tweak_mul(const secp256k1_context* ctx, secp256k1_pubkey *pubkey, const unsigned char *tweak)
    attach_function :secp256k1_ec_pubkey_tweak_mul, [:pointer, :pointer, :pointer], :int
    # int secp256k1_ec_privkey_tweak_mul(const secp256k1_context* ctx, unsigned char *seckey, const unsigned char *tweak)
    attach_function :secp256k1_ec_privkey_tweak_mul, [:pointer, :pointer, :pointer], :int

    # Recovery module
    begin
      # int secp256k1_ecdsa_recoverable_signature_parse_compact(const secp256k1_context *ctx, secp256k1_ecdsa_recoverable_signature *sig, const unsigned char *input64, int recid)
      attach_function :secp256k1_ecdsa_recoverable_signature_parse_compact, [:pointer, :pointer, :pointer, :int], :int
      # int secp256k1_ecdsa_recoverable_signature_convert(const secp256k1_context *ctx, secp256k1_ecdsa_signature *sig, const secp256k1_ecdsa_recoverable_signature *sigin)
      attach_function :secp256k1_ecdsa_recoverable_signature_convert, [:pointer, :pointer, :pointer], :int
      # int secp256k1_ecdsa_recoverable_signature_serialize_compact(const secp256k1_context *ctx, unsigned char *output64, int *recid, const secp256k1_ecdsa_recoverable_signature *sig)
      attach_function :secp256k1_ecdsa_recoverable_signature_serialize_compact, [:pointer, :pointer, :pointer, :pointer], :int
      # int secp256k1_ecdsa_sign_recoverable(const secp256k1_context* ctx, secp256k1_ecdsa_recoverable_signature *sig, const unsigned char *msg32, const unsigned char *seckey, secp256k1_nonce_function noncefp, const void *ndata)
      attach_function :secp256k1_ecdsa_sign_recoverable, [:pointer, :pointer, :pointer, :pointer, :pointer, :pointer], :int
      # int secp256k1_ecdsa_recover(const secp256k1_context* ctx, secp256k1_pubkey* pubkey, secp256k1_ecdsa_recoverable_signature *sig, const unsigned char *msg32)
      attach_function :secp256k1_ecdsa_recover, [:pointer, :pointer, :pointer, :pointer], :int
    rescue FFI::NotFoundError
    end

    # ECDH module
    begin
      # int secp256k1_ecdh(const secp256k1_context* ctx, unsigned char *result, const secp256k1_pubkey *point, const unsigned char *scalar)
      attach_function :secp256k1_ecdh, [:pointer, :pointer, :pointer, :pointer], :int
    rescue FFI::NotFoundError
    end

    # AGGSIG (Schnorr) Multisig
    begin
      # secp256k1_aggsig_context* secp256k1_aggsig_context_create(const secp256k1_context *ctx, const secp256k1_pubkey *pubkeys, size_t n_pubkeys, const unsigned char *seed)
      attach_function :secp256k1_aggsig_context_create, [:pointer, :pointer, :size_t, :pointer], :pointer
      # void secp256k1_aggsig_context_destroy(secp256k1_aggsig_context *aggctx)
      attach_function :secp256k1_aggsig_context_destroy, [:pointer], :void
      # int secp256k1_aggsig_generate_nonce(const secp256k1_context* ctx, secp256k1_aggsig_context* aggctx, size_t index)
      attach_function :secp256k1_aggsig_generate_nonce, [:pointer, :pointer, :size_t], :int
      # int secp256k1_aggsig_partial_sign(const secp256k1_context* ctx, secp256k1_aggsig_context* aggctx, secp256k1_aggsig_partial_signature *partial, const unsigned char *msghash32, const unsigned char *seckey32, size_t index)
      attach_function :secp256k1_aggsig_partial_sign, [:pointer, :pointer, :pointer, :pointer, :pointer, :size_t], :int
      # int secp256k1_aggsig_combine_signatures(const secp256k1_context* ctx, secp256k1_aggsig_context* aggctx, unsigned char *sig64, const secp256k1_aggsig_partial_signature *partial, size_t n_sigs)
      attach_function :secp256k1_aggsig_combine_signatures, [:pointer, :pointer, :pointer, :pointer, :size_t], :int
      # int secp256k1_aggsig_build_scratch_and_verify(const secp256k1_context* ctx, const unsigned char *sig64, const unsigned char *msg32, const secp256k1_pubkey *pubkeys, size_t n_pubkeys)
      attach_function :secp256k1_aggsig_build_scratch_and_verify, [:pointer, :pointer, :pointer, :pointer, :size_t], :int
      # int secp256k1_aggsig_export_secnonce_single(const secp256k1_context* ctx, unsigned char* secnonce32, const unsigned char* seed)
      attach_function :secp256k1_aggsig_export_secnonce_single, [:pointer, :pointer, :pointer], :int
      # int secp256k1_aggsig_sign_single(const secp256k1_context* ctx, unsigned char *sig64, const unsigned char *msg32, const unsigned char *seckey32, const unsigned char* secnonce32, const unsigned char* extra32, const secp256k1_pubkey* pubnonce_for_e, const secp256k1_pubkey* pubnonce_total, const secp256k1_pubkey* pubkey_for_e, const unsigned char* seed)
      attach_function :secp256k1_aggsig_sign_single, [:pointer, :pointer, :pointer, :pointer, :pointer, :pointer, :pointer, :pointer, :pointer, :pointer], :int
      # int secp256k1_aggsig_verify_single(const secp256k1_context* ctx, const unsigned char *sig64, const unsigned char *msg32, const secp256k1_pubkey *pubnonce, const secp256k1_pubkey *pubkey, const secp256k1_pubkey *pubkey_total, const secp256k1_pubkey *extra_pubkey, const int is_partial)
      attach_function :secp256k1_aggsig_verify_single, [:pointer, :pointer, :pointer, :pointer, :pointer, :pointer, :pointer, :int], :int
      # int secp256k1_aggsig_add_signatures_single(const secp256k1_context* ctx, unsigned char *sig64, const unsigned char** sigs, size_t num_sigs, const secp256k1_pubkey* pubnonce_total)
      attach_function :secp256k1_aggsig_add_signatures_single, [:pointer, :pointer, :pointer, :size_t, :pointer], :int
    rescue FFI::NotFoundError
    end

    # Schnorrsig module
    begin
      # int secp256k1_schnorrsig_verify_batch(const secp256k1_context* ctx, secp256k1_scratch_space* scratch, const secp256k1_schnorrsig* const* sig, const unsigned char* const* msg32, const secp256k1_pubkey* const* pk,	size_t n_sigs)
      attach_function :secp256k1_schnorrsig_verify_batch, [:pointer, :pointer, :pointer, :pointer, :pointer, :size_t], :int
    rescue FFI::NotFoundError
    end
  end
end
