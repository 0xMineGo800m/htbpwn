import argparse
import dataclasses
import enum
import ipaddress
import pathlib


class Mode(enum.Enum):
    def _generate_next_value_(name, start, count, last_values):
        return name

    local = enum.auto()
    remote = enum.auto()


@dataclasses.dataclass
class Config:
    rop: bool = False
    no_offset: bool = False
    offset: int = None
    offset_max: int = 0x100

    main_function_name: str = 'main'
    main_function_address: int = None
    mode: Mode = Mode.local

    file: pathlib.Path = None
    ip: ipaddress.IPv4Address = None
    port: int = None

    libc: str = None
    detect_libc: bool = False

    illegal_symbols: bytes = b''

    leave: bool = True  # add rpb to the generated payload
    @staticmethod
    def from_args():
        parser = argparse.ArgumentParser()
        parser.add_argument("--rop", '-R', action='store_true')
        parser.add_argument("--illegal-symbols", '-i', type=str.encode)
        overflow_parser = parser.add_mutually_exclusive_group(required=True)
        overflow_parser.add_argument("--no-offset", action='store_true')
        overflow_parser.add_argument("--offset", "-o", type=lambda x: int(x, 0))
        overflow_parser.add_argument("--offset-max", type=lambda x: int(x, 0), default=0x100)

        main = parser.add_mutually_exclusive_group()
        main.add_argument("--main-function-name", "-m", type=str, default='main')
        main.add_argument("--main-function-address", "-M", type=str)

        mode_parsers = parser.add_subparsers(dest='mode')

        local_parser = mode_parsers.add_parser('local')
        local_parser.add_argument('file', type=pathlib.Path)

        remote_parser = mode_parsers.add_parser('remote')
        remote_parser.add_argument('ip', type=ipaddress.IPv4Address)
        remote_parser.add_argument('port', type=int)
        remote_parser.add_argument('file', type=pathlib.Path)

        libc_parser = parser.add_mutually_exclusive_group(required=True)
        libc_parser.add_argument('--libc', '-l', type=str)
        libc_parser.add_argument('--detect-libc', '-L', action='store_true')

        libc_parser.add_argument('--no-leave', action='store_false', destination='leave')


        return parser.parse_args()