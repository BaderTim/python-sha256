def ascii_to_bits(string):
    """
    :param string: ascii string
    :return: bit array
    """
    result = []
    for c in string:
        bits = bin(ord(c))[2:]
        bits = '00000000'[len(bits):] + bits
        result.extend([int(b) for b in bits])
    return result


def bits_to_hexadecimal(bit_string):
    """
    :param bit_string: bit string
    :return: hexadecimal string
    """
    return hex(int(bit_string, 2)).replace("0x", "")


def bit_array_to_bit_string(bit_array):
    res = ""
    for _, array in enumerate(bit_array):
        for _, bit in enumerate(array):
            res += str(bit)
    return res


def hexadecimal_to_bit_array(input_hexadecimal, bit_length):
    """
    :param input_hexadecimal: hexadecimal number
    :param bit_length: length of binary output
    :return: integer list of binary representation of input
    """
    bit_string = format(input_hexadecimal, f'0>{bit_length}b')
    return [int(i) for i in list(bit_string)]


def int_to_bit_array(input_int):
    """
    :param input_int: input integer
    :return: integer list of binary representation of input_int
    """
    big_endian = "{0:b}".format(input_int)
    return [int(i) for i in list(big_endian)]


def get_chunks(array, size):
    """
    :param array: array of binaries
    :param size: chunk size
    :return: returns array of chunks with the given size of the input array
    """
    res = []
    x = 0
    y = len(array)
    for i in range(x, y, size):
        x = i
        res.append(array[x:x + size])
    return res
