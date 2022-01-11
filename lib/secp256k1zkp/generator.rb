# frozen_string_literal: true

module Secp256k1zkp

  class Generator < FFI::Struct
    layout :data, [:uchar, 64]
  end

  # Generator point G
  GENERATOR_G = '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'
  # Generator point H
  # Used as generator point for the value in Pedersen Commitments.
  GENERATOR_H = '50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac031d3c6863973926e049e637cb1b5f40a36dac28af1766968c30c2313f3a38904'

  module_function

  # Get memory pointer for Generator point G.
  # @return [FFI::MemoryPointer]
  def generator_g_ptr
    Generator.new.pointer.put_bytes(0, [GENERATOR_G].pack('H*'))
  end

  # Get memory pointer for Generator point H.
  # @return [FFI::MemoryPointer]
  def generator_h_ptr
    Generator.new.pointer.put_bytes(0, [GENERATOR_H].pack('H*'))
  end
end
