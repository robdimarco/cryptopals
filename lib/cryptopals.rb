# frozen_string_literal: true

# Takes a string in hex, breaks up in to an array of 2 characters
# and converts the 2 characters to a hex value
#
# @param hex_string - String in hex format
# @returns Array[Integer] - Array of integers representing the converted string
def hex_to_bytes(hex_string)
  hex_string.scan(/../).map(&:hex)
end

# https://cryptopals.com/sets/1

#
# Converts a string in hex format to a string of characters
# @param hex_string - String in hex format
# @returns String with the hex translated in to UTF characters
def hex_to_chars(hex_string)
  hex_to_bytes(hex_string).map(&:chr).join
end

#
# Converts an array of bytes in to a string in hexadecimal format
#
# @param bytes - Array of bytes
# @returns String with hexadecimal representation of the bytes
def bytes_to_hex(bytes)
  bytes.map { |i| format('%<byte>02x', byte: i) }.join
end

#
# Takes two hex strings, converts them to bytes, XORs them, and returns a hex string
#
# @param hex1 - String in hex format
# @param hex2 - String in hex format
# @returns String in hex format which represents the XOR
def xor_hex(hex1, hex2)
  s1b = hex_to_bytes(hex1)
  s2b = hex_to_bytes(hex2)
  xor_bytes(s1b, s2b)
end

#
# Takes two arrays of bytes, XORs them, and returns a hex string representing the bytes.
# Note, both arrays should be of the same length
#
# @param bytes1 - Array of bytes
# @param bytes2 - Array of bytes
# @returns String in hex format which represents the XOR
def xor_bytes(bytes1, bytes2)
  results_in_bytes = (0...bytes1.length).map { |i| bytes1[i] ^ bytes2[i] }
  bytes_to_hex(results_in_bytes)
end

# Takes in a hex string and sees how likely the string is to being
# a sentence.
#
# @param hex_string - Input hex tring
# @returns Float between 0 and 1 representing how likely a string is to being a sentence
def sentence_score(hex_string)
  real_string = hex_to_chars(hex_string).chars
  real_string.map { |i| i.match(/[\w ]/) ? 1 : 0 }.sum / real_string.length.to_f
end

DecodedString = Struct.new(:encoding_byte, :decoded_string)

# Given a hex string XOR'd with a single character, find all possible
# decoded strings.
#
# @param encoded_string - The hex-encoded string that has been XOR'd
# @returns Array of Decoded Strings
def potential_strings_from_single_char_xor(encoded_string)
  # for all bytes...
  (0..255).map do |decoded_char|
    # Create a hex string equal in length to the target
    decoding_string = bytes_to_hex([decoded_char] * encoded_string.length)

    DecodedString.new(
      decoded_char,
      xor_hex(encoded_string, decoding_string)
    )
  end
end

#
# @param string - Plain text string to encrypt
# @param key - Key to encrypt with
# @returns String in hex format which represents the encrypted string
def encrypt(string, key)
  full_key = key * ((string.length / key.length) + 1)
  xor_bytes(string.bytes, full_key[0..string.length].bytes)
end

def find_key_size_for_encrypted_file(string, min_key_size: 2, max_key_size: 40, comparisons: 2)
  bytes = hex_to_bytes(string)
  (min_key_size..max_key_size).to_a.min_by do |key_size|
    blocks = (0...(2*comparisons)).map do |i|
      offset = i * key_size
      bytes[offset...(offset + key_size)]
    end

    distances = (0...comparisons).map do |i|
      block_1 = blocks[i * 2]
      block_2 = blocks[(i * 2) + 1]
      hamming_distance(bytes_to_hex(block_1), bytes_to_hex(block_2)) / key_size.to_f
    end

    # Now get the average distance
    distances.sum / comparisons
  end
end

def hamming_distance(s1, s2)
  s1.bytes.zip(s2.bytes).map { |(a, b)| (a ^ b).to_s(2) }.join.scan('1').size
end

# Takes a hex string that has been XOR'd with a single character and iterates through single characters
# to find the most likely candidate for the decoded string
#
# @param encoded_string - The hex-encoded string that has been XOR'd
# @returns String - The most likely decoded string
def decoded_string_from_hex(encoded_string)
  vals = potential_strings_from_single_char_xor(encoded_string).sort_by do |val|
    -1 * sentence_score(val.decoded_string)
  end

  hex_to_chars(vals[0].decoded_string)
end
