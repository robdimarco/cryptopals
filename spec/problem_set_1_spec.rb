# frozen_string_literal: true

require 'spec_helper'

RSpec.describe 'cryptopals.com Set 1' do # rubocop:disable Metrics/BlockLength
  describe 'challenge 1' do
    let(:input_as_hex) { '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d' }
    let(:output_in_base_64) { 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t' }
    let(:input_converted_to_bytes) { hex_to_chars(input_as_hex) }

    it 'can convert hex to bytes' do
      require 'base64'
      expect(
        Base64.strict_encode64(
          input_converted_to_bytes
        )
      ).to eq(output_in_base_64)
    end
  end

  describe 'challenge 2' do
    let(:input_as_hex) { '1c0111001f010100061a024b53535009181c' }
    let(:xor_against_as_hex) { '686974207468652062756c6c277320657965' }
    let(:expected) { '746865206b696420646f6e277420706c6179' }

    it 'can XOR hex strings' do
      expect(xor_hex(input_as_hex, xor_against_as_hex)).to \
        eq(expected)
    end
  end

  describe 'challenge 3' do
    let(:input_as_hex) { '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736' }
    let(:expected) { "Cooking MC's like a pound of bacon" }

    it 'can get a good sentence score' do
      expect(sentence_score(bytes_to_hex('How now brown cow'.bytes))).to eq(1)
      expect(sentence_score(bytes_to_hex('@**'.bytes))).to eq(0)
    end

    it 'can find a char to decrypt a string' do
      expect(decoded_string_from_hex(input_as_hex)).to eq(expected)
    end
  end
end
