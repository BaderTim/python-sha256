import Converter

#
# Constants
#

# first 32 bits of the *square* roots of the first 8 prime numbers: 2, 3, 5, 7, 11, 13, 17, 19
hash_constants = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]

# first 32 bits of the *cube* roots of the first 64 prime numbers (2 - 311)
round_constants = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                   0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                   0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                   0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                   0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                   0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                   0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                   0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]


#
# SHA256
#

def message_padding(input_string):
    """
    -- STEP 1: PADDING --
    - append 1
    - append 0's until string length is multiple of 512
    - replace last bits with length of initial input
    :param input_string: plaintext string
    :return: padded string as bit array [str,1,0...0,len(str)]  --> [448, 2^64]
    """
    raw_bits = Converter.ascii_to_bits(string=input_string)
    input_length = len(raw_bits)
    if len(Converter.int_to_bit_array(input_int=len(input_string))) > 64:
        raise OverflowError("Input is too long.")

    # append 1 to bit array
    raw_bits.append(1)

    missing_length = 512 - len(raw_bits) % 512
    # check if there is space for big endian (64 bits, representing length of initial string)
    # if not, do padding until next multiple of 512 is reachable
    if missing_length < 64:
        for x in range(missing_length):
            raw_bits.append(0)
        missing_length = 512

    # make space for big endian
    missing_length -= 64
    # padding with 0's
    for x in range(missing_length):
        raw_bits.append(0)

    # get big endian
    big_endian = Converter.int_to_bit_array(input_int=input_length)

    # if big endian does not take up all 64 bits, pad the rest
    for x in range(64 - len(big_endian)):
        raw_bits.append(0)

    # fill in big endian
    for _, bit in enumerate(big_endian):
        raw_bits.append(bit)

    return Converter.get_chunks(array=raw_bits, size=512)


def message_scheduling(message_chunk):
    """
    -- STEP 1: SCHEDULING --
    - splits 512bit message into 16 32bit words
    - generates 48 more words with existing words and bit operations
    :param message_chunk: 512 bit long message chunk
    :return: 64 32bit word chunks
    """
    # split message into 32 bit words
    word_chunks = Converter.get_chunks(array=message_chunk, size=32)

    # add 48 more empty words --> 64 in total
    for x in range(48):
        word_chunks.append([0] * 32)

    # carousel goes brr
    # basically, each word gets re-created by its predecessor mixed with bit operation functions
    for count in range(16, len(word_chunks)):
        # combine bit operations with xor
        s0_operation = xor(
            xor(
                right_rotate(array=word_chunks[count - 15], distance=7),
                right_rotate(array=word_chunks[count - 15], distance=18)),
            right_shift(array=word_chunks[count - 15], distance=3)
        )
        s1_operation = xor(
            xor(
                right_rotate(array=word_chunks[count - 2], distance=17),
                right_rotate(array=word_chunks[count - 2], distance=19)),
            right_shift(array=word_chunks[count - 2], distance=10)
        )
        # add bit operation results together with other words
        word_chunks[count] = add(array_alpha=word_chunks[count - 16], array_beta=add(
            array_alpha=s0_operation, array_beta=add(
                array_alpha=word_chunks[count - 7], array_beta=s1_operation)))

    return word_chunks


def compression(word_chunks, bit_hash_constants):
    """
    :param word_chunks: 64 long array of 32 bit words
    :param bit_hash_constants: constants for mutating
    :return: returns mutated constants
    """

    # get bit hash constant variables
    var_a = bit_hash_constants[0]
    var_b = bit_hash_constants[1]
    var_c = bit_hash_constants[2]
    var_d = bit_hash_constants[3]
    var_e = bit_hash_constants[4]
    var_f = bit_hash_constants[5]
    var_g = bit_hash_constants[6]
    var_h = bit_hash_constants[7]

    # mutate variables with given word chunks and bit operations
    for count, word in enumerate(word_chunks):
        # bit operations with current constants
        s1_op = xor(
            xor(
                right_rotate(var_e, 6),
                right_rotate(var_e, 11)
            ),
            right_rotate(var_e, 25)
        )
        s0_op = xor(
            xor(
                right_rotate(var_a, 2),
                right_rotate(var_a, 13)
            ),
            right_rotate(var_a, 22)
        )
        ch_op = xor(bit_and(var_e, var_f), bit_and(bit_not(var_e), var_g))
        temp_1 = add(array_alpha=var_h,
                     array_beta=add(array_alpha=s1_op,
                                    array_beta=add(array_alpha=ch_op,
                                                   array_beta=add(
                                                       array_alpha=Converter.hexadecimal_to_bit_array(
                                                           input_hexadecimal=round_constants[count], bit_length=32),
                                                       array_beta=word))))
        maj_op = xor(
            bit_and(var_a, var_b),
            xor(
                bit_and(var_a, var_c),
                bit_and(var_b, var_c)
             )
        )
        # mutate and save constants
        temp_2 = add(s0_op, maj_op)
        var_h = var_g.copy()
        var_g = var_f.copy()
        var_f = var_e.copy()
        var_e = add(var_d, temp_1)
        var_d = var_c.copy()
        var_c = var_b.copy()
        var_b = var_a.copy()
        var_a = add(temp_1, temp_2)

    return [var_a, var_b, var_c, var_d, var_e, var_f, var_g, var_h]


def right_rotate(array, distance):
    """
    :param array: array that should be rotated
    :param distance: the distance of the rotation
    :return: rotated array
    """
    for d in range(distance):
        # one rotation
        temp_array = array.copy()
        for count, _ in enumerate(array):
            if count == 0:
                # move the last element to first pos
                temp_array[0] = array[len(array) - 1]
            else:
                # get element from 1 pos before
                temp_array[count] = array[count - 1]
        array = temp_array
    return array


def right_shift(array, distance):
    """
    :param array: array that should be shifted
    :param distance: the distance of the shifting
    :return: shifted array
    """
    for d in range(distance):
        temp_array = array.copy()
        # one shift
        for count, _ in enumerate(array):
            if count == 0:
                # fill first value with 0
                temp_array[0] = 0
            else:
                # get element from 1 pos before
                temp_array[count] = array[count - 1]
        array = temp_array
    return array


def xor(array_alpha, array_beta):
    """
    :param array_alpha: bit_array alpha
    :param array_beta: bit_array beta
    :return: xor result of alpha and beta
    """
    result = [0] * len(array_alpha)
    for count, bit_alpha in enumerate(array_alpha):
        # bit comparison
        if bit_alpha != array_beta[count]:
            # if not equal, return 1
            result[count] = 1
    return result


def bit_and(array_alpha, array_beta):
    """
    :param array_alpha: bit_array alpha
    :param array_beta: bit_array beta
    :return: and result of alpha and beta
    """
    result = [0] * len(array_alpha)
    for count, bit_alpha in enumerate(array_alpha):
        # bit comparison
        if bit_alpha == 1 and array_beta[count] == 1:
            result[count] = 1
    return result


def bit_not(array):
    """
    :param array: bit_array
    :return: not result of array
    """
    result = [0] * len(array)
    for count, bit_alpha in enumerate(array):
        # bit comparison
        if bit_alpha == 0:
            result[count] = 1
    return result


def add(array_alpha, array_beta):
    """
    :param array_alpha: bit_array alpha
    :param array_beta: bit_array beta
    :return: returns sum of alpha and beta
    """
    result = [0] * len(array_alpha)
    overflow = 0
    for count in range(len(array_alpha) - 1, -1, -1):
        # calculates bit addition
        state = overflow + array_alpha[count] + array_beta[count]
        # evaluates the addition result
        if state == 1:
            overflow = 0
            result[count] = 1
        elif state == 2:
            overflow = 1
        elif state == 3:
            overflow = 1
            result[count] = 1
    return result


def sha256(input_string):
    """
    !ENTRY POINT!
     - SHA256 core function: padding -> message scheduling
    :param input_string: input string to hash
    :return: sha256 hash of string
    """
    # convert hexadecimal hash constants to 32bit binary variables
    var_a = Converter.hexadecimal_to_bit_array(input_hexadecimal=hash_constants[0], bit_length=32)
    var_b = Converter.hexadecimal_to_bit_array(input_hexadecimal=hash_constants[1], bit_length=32)
    var_c = Converter.hexadecimal_to_bit_array(input_hexadecimal=hash_constants[2], bit_length=32)
    var_d = Converter.hexadecimal_to_bit_array(input_hexadecimal=hash_constants[3], bit_length=32)
    var_e = Converter.hexadecimal_to_bit_array(input_hexadecimal=hash_constants[4], bit_length=32)
    var_f = Converter.hexadecimal_to_bit_array(input_hexadecimal=hash_constants[5], bit_length=32)
    var_g = Converter.hexadecimal_to_bit_array(input_hexadecimal=hash_constants[6], bit_length=32)
    var_h = Converter.hexadecimal_to_bit_array(input_hexadecimal=hash_constants[7], bit_length=32)
    bit_hash_constants = [var_a, var_b, var_c, var_d, var_e, var_f, var_g, var_h]
    bit_hash_variables = bit_hash_constants.copy()

    # step 1: padding
    message_chunks = message_padding(input_string)

    for _, chunk in enumerate(message_chunks):
        # step 2: message scheduling
        words = message_scheduling(message_chunk=chunk)

        # step 3: compressing
        compressed_words = compression(word_chunks=words, bit_hash_constants=bit_hash_variables)

        bit_result = []
        # step 4: bit_add operation of initial constants and mutated result
        for count in range(len(bit_hash_variables)):
            bit_result.append(add(compressed_words[count], bit_hash_constants[count]))
        bit_hash_variables = bit_result

    # convert bit array to string
    combined_variables = Converter.bit_array_to_bit_string(bit_hash_variables)
    return Converter.bits_to_hexadecimal(combined_variables)


if __name__ == "__main__":
    word = "hello world"
    print(f"Hashing '{word}' ...")
    print(f"Result: {sha256(word)}")
