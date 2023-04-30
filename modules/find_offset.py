import threading
from typing import Optional

import pwnlib
from pwnlib.util.cyclic import cyclic, cyclic_find

from abstract.module import AbstractModule
from abstract.pwntarget import CustomOffsetFinderMixin
from core.gdb_wrapper import GdbWrapper, GdbApi
from core.targetbase import TargetBase


class FindOffset(AbstractModule):
    thread_timeout = 5
    @classmethod
    def execute(cls, target: TargetBase, max_offset: int, *args, **kwargs) -> Optional:
        def _signal_handler(event):
            cls.logger.success(f'Stop signal caught')
            if event.stop_signal == 'SIGSEGV':
                cls.logger.info('Received SIGSEGV')
            else:
                cls.logger.warning(f'Received another signal: {event.stop_signal}')
            result = debugger.read_value('$rsp', to_string=True)
            value = int(result.split('\t')[1].strip(), base=16)
            offset = cyclic_find(value)
            if offset != -1:
                cls.logger.success(f'Found offset: {hex(offset)}')
                target.offset = offset
                sighandler_done.set()
        cls.logger.info(f"Running {cls.__name__} module")
        if target.offset:
            cls.logger.info(f"Offset is already set ({hex(target.offset)})")
            return target.offset
        cls.logger.info('Looking for the offset')
        cls.logger.info('Starting up the debugger...')
        with GdbWrapper(target.file.path) as debugger:
            sighandler_done = threading.Event()
            cls.logger.info(f'Setting up signal callback')
            debugger.api().events.stop.connect(_signal_handler)
            debugger.resume()
            if isinstance(target.pwn_target, CustomOffsetFinderMixin):
                cls.logger.info(f"Using a custom offset finder for {target.pwn_target.__class__.__name__}")
                target.pwn_target.find_offset(target.process, debugger, max_offset)
            else:
                cls._find_offset(target, target.process, debugger, max_offset)
            if not sighandler_done.wait(timeout=cls.thread_timeout):
                cls.logger.critical("Failed to trigger overflow")
            cls.logger.info("Cleaning up gdb")
            debugger.resume()

    @classmethod
    def _find_offset(cls, target: TargetBase, proc: pwnlib.tubes.process, _: GdbApi, max_offset: int):
        cls.logger.info(f'Generating payload, size={hex(max_offset)}')
        payload = cyclic(max_offset)
        cls.logger.info(f'Running main...')
        target.pwn_target.main(proc, payload, pwn_target=target.pwn_target)
