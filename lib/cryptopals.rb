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

# def encrypt(s, key)
#   full_key = key * ((s.length / key.length) + 1)
#   xor_bytes(s.bytes, full_key[0..s.length].bytes)
# end

# def hamming_distance(s1, s2)
#   s1.bytes.zip(s2.bytes).map { |(a, b)| (a ^ b).to_s(2) }.join.scan('1').size
# end

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

# def prob3
#   s = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
# end

# def prob4
#   require 'net/http'
#   strings = Net::HTTP.get(URI('https://cryptopals.com/static/challenge-data/4.txt')).lines.map(&:strip)
#   pairs = strings.flat_map do |s|
#     potential_strings_from_single_char_xor(s)
#   end
#   best = pairs.min_by { |(_, s)| -1 * sentence_score(s) }
#   [str_to_bin(best[1]), best[0], best[1]]
# end

# def prob5
#   s = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
#   encrypt(s, 'ICE')
# end

# def prob6
#   data = ''
#   (2..40).each do |keysize|
#   end
# end
