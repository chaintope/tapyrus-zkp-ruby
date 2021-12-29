# frozen_string_literal: true

RSpec.describe Secp256k1zkp do
  it "has a version number" do
    expect(Secp256k1zkp::VERSION).not_to be nil
  end
end
