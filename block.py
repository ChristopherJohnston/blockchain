from hashlib import sha256
import time
import struct
import binascii
import datetime

VERSION = 1

def hexify(value, type):
    return binascii.hexlify(struct.Struct(type).pack(value))

def get_block_header(hash_merkle_root, previous_hash, timestamp, bits, nonce):
    '''
    SEE: https://en.bitcoin.it/wiki/Block_hashing_algorithm

    header comprises:

    |================+============================================================+=========================================================+==============|
    | Field	         | Purpose                                                    | Updated when...	                                        | Size (Bytes) |
    |================|============================================================|=========================================================|==============|
    | Version	       | Block version number	                                      | You upgrade the software and it specifies a new version	| 4            |
    | hashPrevBlock  | 256-bit hash of the previous block header	                | A new block comes in	                                  | 32           |
    | hashMerkleRoot | 256-bit hash based on all of the transactions in the block |	A transaction is accepted	                              | 32           |
    | Time        	 | Current timestamp as seconds since 1970-01-01T00:00 UTC	  | Every few seconds                                     	| 4            |
    | Bits	         | Current target in compact format	                          | The difficulty is adjusted	                            | 4            |
    | Nonce	         | 32-bit number (starts at 0)	                              | A hash is tried (increments)	                          | 4            |
    |================+============================================================+=========================================================+==============|
    '''
    # Example header using data from https://blockchain.info/block/00000000000000001e8d6829a8a21adc5d38d0a473b144b6765798e61f98bd1d
    # header_hex = ("01000000" +
    #  "81cd02ab7e569e8bcd9317e2fe99f2de44d49ab2b8851ba4a308000000000000" +
    #  "e320b6c2fffc8d750423db8b1eb942ae710e951ed797f7affc8892b0f1fc122b" +
    #  "c7f5d74d" +
    #  "f2b9441a" +
    #  "42a14695")
    header_hex = '{version}{previous_hash}{hash_merkle_root}{timestamp}{bits}{nonce}'.format(
        version=hexify(VERSION, '<L'),
        previous_hash=binascii.hexlify(previous_hash.decode('hex')[::-1]),
        hash_merkle_root=binascii.hexlify(hash_merkle_root.decode('hex')[::-1]),
        timestamp=hexify(timestamp, '<L'),
        bits=hexify(bits, "<L"),
        nonce=hexify(nonce, '<L')
    )
    header_bin = header_hex.decode('hex')
    return header_bin

def calculate_target(bits):
    # http://www.righto.com/2014/02/bitcoin-mining-hard-way-algorithms.html
    # https://gist.github.com/shirriff/cd5c66da6ba21a96bb26#file-mine-py
    # https://gist.github.com/shirriff/cd5c66da6ba21a96bb26#file-mine-py
    # https://en.bitcoin.it/wiki/Difficulty
    exp = bits >> 24
    mant = bits & 0xffffff
    target_hexstr = '%064x' % (mant * (1<<(8*(exp - 3))))
    target_str = target_hexstr.decode('hex')
    return target_str

def calc_hash(block):
    hash = sha256(sha256(block).digest()).digest()
    return hash[::-1]

def find_hash(block_number, data, difficulty_bits, previous_hash, initial_nonce=0, max_attempts=1000000000, timestamp=None):
    print 'Find hash for block {0} with difficulty {1}'.format(block_number, difficulty_bits)
    complete = False
    nonce = initial_nonce
    attempts = 0
    h = None

    while True:
        timestamp = timestamp or int(time.time())
        block = get_block_header(data, previous_hash, timestamp, difficulty_bits, nonce)
        h = calc_hash(block)
        target = calculate_target(difficulty_bits)
        if h < target:
            complete = True
            break

        nonce += 1
        attempts += 1

        if attempts > max_attempts:
            break
    
    return dict(
        block_number=block_number,
        timestamp=timestamp,
        data=data,
        previous_hash=previous_hash,
        bits=difficulty_bits,
        complete=complete,
        attempts=attempts,
        nonce=nonce if complete else None,
        hash=h.encode('hex') if complete else None
    )

def run_block(chain, block_number, data, difficulty_bits, initial_nonce=0, max_attempts=1000000000):
    previous_hash = chain[block_number-1].get('hash') if block_number>0 else '0'*64
    result = find_hash(block_number, data, difficulty_bits, previous_hash, initial_nonce, max_attempts)
    print result
    chain.append(result)
    return chain

def verify(result, previous_hash):
    nonce = result.get('nonce')
    hash = result.get('hash')
    block_number = result.get('block_number')
    data = result.get('data')
    timestamp = result.get('timestamp')
    bits = result.get('bits')

    block = get_block_header(data, previous_hash, timestamp, bits, nonce)
    new_hash = calc_hash(block).encode('hex_codec')
    return dict(hash=new_hash, valid=new_hash == hash)

def verify_chain(chain):
    print 'verifying chain...'
    results = {}
    previous_hash = '0'*64
    for block in chain:
        block_number = block.get('block_number')
        result = verify(block, previous_hash)
        previous_hash = result['hash']
        results[block_number] = result['valid']
    return results

def calc_chain():
    print 'Calculating example chain...'
    data = sha256('hello').digest()[::-1].encode('hex')
    difficulty_bits = 0x1f00ffff
    max_attempts = 1000000000

    # Run Chain once
    chain = []
    for block_number in range(4):
        run_block(chain, block_number, data, difficulty_bits, 0, max_attempts)
        block_number += 1
    
    print verify_chain(chain)

    print 'injecting different data at block 1....'
    # Change some data and find new hash
    new_result = find_hash(
        chain[1]['block_number'],
        sha256('world').digest()[::-1].encode('hex'),
        difficulty_bits,
        chain[0]['hash'],
        0,
        max_attempts,
        chain[1]['timestamp']
    )

    chain[1] = new_result
    print 'verifying chain again...'
    print verify_chain(chain)

def calc_block_125552():
    # from block 125552
    # see https://blockchain.info/block/00000000000000001e8d6829a8a21adc5d38d0a473b144b6765798e61f98bd1d
    # see https://blockexplorer.com/block/00000000000000001e8d6829a8a21adc5d38d0a473b144b6765798e61f98bd1d
    print 'Calculating and verifying hash for block 125552...'
    prev_block_hash = '00000000000008a3a41b85b8b29ad444def299fee21793cd8b9e567eab02cd81'
    hash_merkle_root = '2b12fcf1b09288fcaff797d71e950e71ae42b91e8bdb2304758dfcffc2b620e3'
    bits = 0x1a44b9f2
    timestamp = 1305998791
    nonce = 2504433986

    # a = struct.Struct('I')
    # print datetime.datetime.fromtimestamp(s.unpack('c7f5d74d'.decode('hex'))[0])
    # print s.unpack('f2b9441a'.decode('hex'))
    # print s.unpack('42a14695'.decode('hex'))

    # https://en.bitcoin.it/wiki/Difficulty
    # https://bitcoin.stackexchange.com/questions/30467/what-are-the-equations-to-convert-between-bits-and-difficulty
    # difficulty from bits
    # bits = 1a44b9f2
    # 0x1a = number of bytes in a target, 0x44b9f2 = target prefix
    # Genesis block difficulty = 0x1d00ffff
    # print 0x00ffff * 2**(8*(0x1d - 3)) / float(0x44b9f2 * 2**(8*(0x1a - 3)))

    # Calc hash and check if it's less than the target
    target = calculate_target(bits)
    header = get_block_header(hash_merkle_root, prev_block_hash, timestamp, bits, nonce)
    hash = calc_hash(header)
    print 'Hash: {0}'.format(hash.encode('hex_codec'))
    print 'Target: {0}'.format(target.encode('hex'))
    print 'Valid Hash: {0}'.format(hash < target)

    # find the hash through iteration
    print find_hash(125552, hash_merkle_root, bits, prev_block_hash, initial_nonce=nonce-2, max_attempts=1000000000, timestamp=timestamp)
    print

def main():
    calc_block_125552()
    calc_chain()

main()
