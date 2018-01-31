# this code based on pseudocode from wikipedia
# https://en.wikipedia.org/wiki/SHA-1#SHA-1_pseudocode

# initialise nothing-up-my-sleeve numbers
# https://www.youtube.com/watch?v=oJWwaQm-Exs
h_0 = 0x67452301
h_1 = 0xEFCDAB89
h_2 = 0x98BADCFE
h_3 = 0x10325476
h_4 = 0xC3D2E1F0


# we'll use these later
def leftrotate_32(byte_array_to_shift, bits):
    # we'll have to cast to int and back since you can't bit-shift bytearrays
    bit_string = int.from_bytes(byte_array_to_shift, 'big')

    # shift
    bit_string <<= bits

    # take overflowed bits
    overflow = (((2**bits - 1) << 32) & bit_string) >> 32  # bit mask

    # put on end
    bit_string |= overflow

    # return
    return int_to_bytearray(bit_string, 4)


def int_to_bytearray(integer, n_bytes):
    return_bytes = bytearray(n_bytes)
    for ii in range(n_bytes):
        shift = (n_bytes - ii - 1) * 8
        this_byte = ((0xFF << shift) & integer) >> shift  # moving byte-sized bit mask
        return_bytes[ii] = this_byte

    return return_bytes


# input message
raw_input = input("Message to hash: ")
# raw_input = "Hello, world!"

# encode as bytearray using ascii encoding
byte_input = bytearray(raw_input, 'ascii')

# message length
# N.B. technically should force to be 64 bits, but since 2^64 - 1 = 18446744073709551615, it's unlikely to overflow.
# for reference, this is more than 1 EiB = 1024 PiB = 1,048,576 TiB = 1,073,741,824 GiB
# so unless your file is approaching a billion GB in size, i wouldn't worry ;)
#
# side-note: this is, of course, an example of hilarious lack of foresight on my part, if you're reading this from the
# distant future. when they were allocating telephone numbers, they made exactly the same assumption, and ran into
# problems later on.
# if you're living in this future world, where files are routinely billions of gigabytes in size, simply uncomment the
# following line (and remove the space, which i put there because pycharm screamed at me):
# message_length |= (2**64 - 1)
message_length = len(byte_input) << 3

# pre-processing
# append bit '1' to message
byte_input.append(0x80)  # this works because there's no way the length will be divisible by 64 between the 1 and 0

# how many empty bytes do you now need to add?
while not len(byte_input) % 64 == 56:
    byte_input.append(0)

# now append the message length as a 64-bit (8-byte) integer
# sadly, i will have to do this by hand
# TODO: find a better way!
for i in range(8):
    byte = (0xFF << (7-i)*8) & message_length  # moving byte-sized (pun intended) bit mask
    byte_input.append(byte)

# break message into 512-bit (64-byte) chunks
chunks_512 = []  # will be a list of bytearrays
for i in range(len(byte_input) // 64):  # integer division (it will certainly be divisible)
    chunks_512.append(byte_input[64*i:64*(i + 1)])

# here we go
for chunk in chunks_512:
    # break each chunk into sixteen 32-bit (4-byte) words
    words = []
    for i in range(16):
        words.append(chunk[4*i:4*(i + 1)])

    # extend the sixteen words to eighty words
    for i in range(16, 80):
        words.append(
            leftrotate_32(int_to_bytearray(
                int.from_bytes(words[i - 3], 'big') ^
                int.from_bytes(words[i - 8], 'big') ^
                int.from_bytes(words[i - 14], 'big') ^
                int.from_bytes(words[i - 16], 'big'),
                4), 1)
        )

    # initialise hash value for this chunk
    a = h_0
    b = h_1
    c = h_2
    d = h_3
    e = h_4
    f = None
    k = None

    # main hashing loop
    for i in range(80):
        if i in range(20):
            f = (b & c) | ((~b) & d)
            k = 0x5A827999
        elif i in range(20, 40):
            f = b ^ c ^ d
            k = 0x6ED9EBA1
        elif i in range(40, 60):
            f = (b & c) | (b & d) | (c & d)
            k = 0x8F1BBCDC
        else:
            f = b ^ c ^ d
            k = 0xCA62C1D6

        temp = leftrotate_32(int_to_bytearray(a, 4), 5)
        temp = int.from_bytes(temp, 'big')
        temp += (f + e + k + int.from_bytes(words[i], 'big'))
        temp &= 0xFFFFFFFF  # 32-bit mask
        e = d
        d = c
        c = int.from_bytes(leftrotate_32(int_to_bytearray(b, 4), 30), 'big')
        b = a
        a = temp

    # add to result so far
    h_0 += a
    h_1 += b
    h_2 += c
    h_3 += d
    h_4 += e

    # remember to bit mask!
    h_0 &= 0xFFFFFFFF
    h_1 &= 0xFFFFFFFF
    h_2 &= 0xFFFFFFFF
    h_3 &= 0xFFFFFFFF
    h_4 &= 0xFFFFFFFF

# produce final hash value
hh = (h_0 << 128) | (h_1 << 96) | (h_2 << 64) | (h_3 << 32) | h_4

# print result in hex
print("Input: {}\nHash: {:X}".format(raw_input, hh))
