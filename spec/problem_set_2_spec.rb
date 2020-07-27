# frozen_string_literal: true

require 'spec_helper'

RSpec.describe 'cryptopals.com Set 2' do
  describe 'challenge 9' do
    let(:input) { 'YELLOW SUBMARINE' }
    let(:block_length) { 20 }
    let(:expected) { "YELLOW SUBMARINE\x04\x04\x04\x04" }

    it 'can convert hex to bytes' do
      expect(pkcs7_pad(input, block_length)).to eq(expected)
    end
  end

  describe 'challenge 10' do
  end
end
