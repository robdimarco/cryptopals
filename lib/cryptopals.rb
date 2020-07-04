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

# def hex_to_str(bytes)
#   bytes.map { |i| '%02x' % i }.join
# end

# def xor_str(s1, s2)
#   s1b = hex_string_to_hex_a(s1)
#   s2b = hex_string_to_hex_a(s2)
#   xor_bytes(s1b, s2b)
# end

# def xor_bytes(b1, b2)
#   results_in_bytes = (0...b1.length).map { |i| b1[i] ^ b2[i] }
#   hex_to_str(results_in_bytes)
# end

# def sentence_score(s)
#   str_to_bin(s).chars.map { |i| i.match(/[\w\s\d]/) ? 1 : 0 }.sum / s.length.to_f
# end

# def potential_strings_from_single_char_xor(s)
#   (0..255).map do |h|
#     xor = hex_to_str([h] * s.length)
#     rv = xor_str(s, xor)
#     [h, rv]
#   end
# end

# def encrypt(s, key)
#   full_key = key * ((s.length / key.length) + 1)
#   xor_bytes(s.bytes, full_key[0..s.length].bytes)
# end

# def hamming_distance(s1, s2)
#   s1.bytes.zip(s2.bytes).map { |(a, b)| (a ^ b).to_s(2) }.join.scan('1').size
# end

# def prob2
#   s = '1c0111001f010100061a024b53535009181c'
#   xor = '686974207468652062756c6c277320657965'
#   xor_str(s, xor)
# end

# def prob3
#   s = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
#   vals = potential_strings_from_single_char_xor(s).sort_by { |(_, s)| -1 * sentence_score(s) }

#   vals[0]
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
