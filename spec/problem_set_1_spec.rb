# frozen_string_literal: true

require 'spec_helper'
require 'securerandom'
require 'base64'

RSpec.describe 'cryptopals.com Set 1' do # rubocop:disable Metrics/BlockLength
  describe 'challenge 1' do
    let(:input_as_hex) { '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d' }
    let(:output_in_base_64) { 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t' }
    let(:input_converted_to_bytes) { hex_to_chars(input_as_hex) }

    it 'can convert hex to bytes' do
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
      expect(sentence_score(bytes_to_hex('How now brown cow'.bytes))).to eq(1.0)
      expect(sentence_score(bytes_to_hex('@**'.bytes))).to eq(0.5)
    end

    it 'can find a char to decrypt a string' do
      expect(decoded_string_from_hex(input_as_hex)).to eq(expected)
    end
  end

  describe 'challenge 4' do
    let(:file_path) { 'data/set-1-challenge-4.txt' }
    it 'has file' do
      expect(File.exist?(file_path)).to be(true), 'Missing file. Redownload from https://cryptopals.com/sets/1/challenges/4'
    end

    it 'can find the single character encrypted string', speed: :slow do
      strings = File.read(file_path).lines.map(&:strip)
      potential_strings = strings.flat_map do |s|
        potential_strings_from_single_char_xor(s)
      end
      best = potential_strings.max_by { |val| sentence_score(val.decoded_string) }

      expect("Now that the party is jumping\n").to eq(hex_to_chars(best.decoded_string))
    end
  end

  describe 'challenge 5' do
    let(:input) { "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal" }
    let(:key) { 'ICE' }
    let(:encrypted_string) { encrypt(input, key) }
    let(:expected) do
      '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272' \
        'a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'
    end

    it 'will encrypt successfully' do
      expect(encrypted_string).to eq(expected)
    end
  end

  describe 'challenge 6' do # rubocop:disable Metrics/BlockLength
    let(:file_path) { 'data/set-1-challenge-6.txt' }
    let(:file_data) { File.read(file_path).lines.map(&:strip).join }

    it 'has file' do
      expect(File.exist?(file_path)).to be(true), 'Missing file. Redownload from https://cryptopals.com/sets/1/challenges/6'
    end

    it 'can parse the file' do
      file_data_as_bytes = Base64.decode64(file_data).bytes
      file_data_as_hex = bytes_to_hex(file_data_as_bytes)
      key = find_encoding_bytes_for_string(file_data_as_hex)
      expect(hex_to_chars(encrypt(hex_to_chars(file_data_as_hex), key.map(&:chr).join))).to match(/Vanilla Ice/)
    end

    describe 'hamming_distance' do
      it 'calculates correct value' do
        expect(hamming_distance('this is a test', 'wokka wokka!!!')).to eq(37)
      end
    end

    describe 'with test encrypted strings' do
      let(:test_input) { File.read(__FILE__) }
      let(:test_key_in_bytes) { SecureRandom.random_bytes(23).bytes }
      let(:test_key_in_hex) { bytes_to_hex(test_key_in_bytes) }
      let(:test_key_in_s) { hex_to_chars(test_key_in_hex) }
      let(:encrypted_string) { encrypt(test_input, test_key_in_s) }

      describe 'find_key_size_for_encrypted_file' do
        it 'calculates the correct key size' do
          expect(find_key_size_for_encrypted_file(encrypted_string)).to \
            eq(test_key_in_bytes.length)
        end
      end

      describe 'string_to_arrays_of_same_encrypted_bytes' do
        it 'creates the correct arrays' do
          byte_arrays = string_to_arrays_of_same_encrypted_bytes(encrypted_string)
          expect(byte_arrays.size).to eq(test_key_in_bytes.length)
          expect(byte_arrays[0].length).to eq((test_input.length / test_key_in_bytes.length) + 1)
          expect(byte_arrays.sum(&:size)).to eq(test_input.length)
        end
      end

      describe 'find_encoding_bytes_for_string', speed: :slow do
        it 'calculates the encoding bytes' do
          expect(find_encoding_bytes_for_string(encrypted_string)).to eq(test_key_in_bytes)
        end
      end
    end
  end
end
