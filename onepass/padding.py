def pkcs5_pad(inp, block_size=16):
    if block_size <= 0:
        raise ValueError("block_size must be a positive integer")

    padding_len = block_size - (len(inp) % block_size)
    padding = chr(padding_len) * padding_len
    return inp + padding


def pkcs5_unpad(inp, block_size=16):
    if len(inp) == 0:
        return inp

    padding_len = ord(inp[-1])
    if padding_len >= block_size:
        return inp

    return inp[:-padding_len]
