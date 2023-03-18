import sqlite3
import tempfile
import typing
from collections import Counter
from typing import Optional

import requests
from loguru import logger
from pwnlib.elf import ELF


class LibcMetadata:
    def __init__(self, name: str = 'unknown', url: Optional[str] = None):
        self.name = name
        self.url = url


def default_filter(name: str):
    return True


class LibcFinder:
    api_url = 'https://libc.rip/api/find'

    @classmethod
    def find_lib(cls, functions: typing.List[typing.Tuple[str, int]], custom_filter: typing.Callable):
        logger.info(f"Getting possible libc version from {cls.api_url}")
        response = requests.post(cls.api_url, json={'symbols': dict((function, hex(address)[-4:]) for function, address in functions)})
        if response.ok:
            variants = response.json()
            logger.info(f"Got {len(variants)} possible results (pre-filtering):")
            logger.debug(', '.join(x['id'] for x in variants))
            return tuple(LibcMetadata(x['id'], x["download_url"]) for x in variants if custom_filter(x))
        return None


class LocalLibcFinder:
    db_path = '/opt/libcdb/libc.db'

    sizes = {
        'read': 0x20,
        '__libc_start_main': 0x140
    }
    default_size = 0x100

    @classmethod
    def get_lib_by_name(cls, name: str, functions: typing.List[typing.Tuple[str, int]]):
        logger.info(f"Getting possible libc version from {cls.db_path}")
        connection = sqlite3.connect(cls.db_path)
        cursor = connection.cursor()
        cursor.execute('select data, id from libc where name=?', (name,))
        result = cursor.fetchone()
        bases = []

        for function_name, function_address in functions:
            cursor.execute('select id from symbol where name=?', (function_name, ))
            symbol_id = cursor.fetchone()[0]
            cursor.execute(
                'select address from symbol2address where (symbol_id = ?) and (libc_id = ?)',
                (symbol_id, result[1])
            )
            value = cursor.fetchone()[0]
            base = function_address - ((function_address - value) & 0xFF) - value
            bases.append(base)
        cursor.close()
        connection.close()
        if not all(b == bases[0] for b in bases):
            logger.warning('bases are not equal')
        return result[0], bases[0]

    @classmethod
    def find_lib(cls, functions: typing.List[typing.Tuple[str, int]], custom_filter: typing.Callable):
        logger.info(f"Getting possible libc version from {cls.db_path}")
        connection = sqlite3.connect(cls.db_path)
        cursor = connection.cursor()
        function_addresses = {}

        for function_name, function_address in functions:
            cursor.execute('select id from symbol where name=?', (function_name, ))
            result = cursor.fetchone()[0]
            cursor.execute(
                'select libc_id, address from symbol2address where (symbol_id = ?) and ((address & 0xFFF) = ?)',
                (result, function_address & 0xFFF)
            )
            values = cursor.fetchall()
            function_addresses[function_name] = dict((x[0], x[1]) for x in values)

        keys = set(function_addresses[functions[0][0]])
        for function in functions[1:]:
            function_name = function[0]
            keys.intersection_update(function_addresses[function_name])

        possible_choices = Counter()
        bases = {}
        for libc in keys:
            sample_function_name, sample_function_address = functions[0]
            address = function_addresses[sample_function_name][libc]
            base = sample_function_address - address
            bases[libc] = base
            for function in functions[1:]:
                another_address = function_addresses[function[0]][libc]
                if (function[1] - another_address) == base:
                    possible_choices[libc] += 1
        results = {}
        for choice in possible_choices:
            cursor.execute('select name,data from libc where id=?', (choice,))
            result = cursor.fetchone()
            if not custom_filter(result[0]):
                logger.info(f'skipping: {result[0]} because of filter')
                continue
            results[result[0]] = result[1], bases[choice]
            logger.info(f"possible libc: {result[0]}@{hex(bases[choice])}, confidence {(possible_choices[choice]+1)/len(functions)}")
        cursor.close()
        connection.close()
        return results
