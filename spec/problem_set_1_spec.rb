# frozen_string_literal: true

require 'spec_helper'

RSpec.describe 'cryptopals.com Set 1' do
  describe 'challenge 1' do
    let(:input_as_hex) { '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d' }
    let(:output_in_base_64) { 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t' }
    let(:input_converted_to_bytes) { hex_to_binary(input_as_hex) }

    it 'can convert hex to bytes' do
      require 'base64'
      expect(
        Base64.strict_encode64(
          input_converted_to_bytes
        )
      ).to.eq(output_in_base_64)
    end
  end
end
