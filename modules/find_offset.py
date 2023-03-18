import threading
from typing import Optional

import pwnlib
from pwnlib import gdb
from pwnlib.util.cyclic import cyclic, cyclic_find

from abstract.module import AbstractModule
from abstract.pwntarget import CustomOffsetFinderMixin
from core.targetbase import TargetBase
from loguru import logger


class FindOffset(AbstractModule):
    thread_timeout = 5
    @classmethod
    def execute(cls, target: TargetBase, max_offset: int, *args, **kwargs) -> Optional:
        def _signal_handler(event):
            logger.success(f'Stop signal caught')
            if event.stop_signal == 'SIGSEGV':
                logger.info('Received SIGSEGV')
            else:
                logger.warning(f'Received another signal: {event.stop_signal}')
            result = debugger.execute('x/wx $rsp', to_string=True)
            value = int(result.split('\t')[1].strip(), base=16)
            offset = cyclic_find(value)
            if offset != -1:
                logger.success(f'Found offset: {hex(offset)}')
                target.offset = offset
                sighandler_done.set()
        logger.info(f"Running {cls.__name__} module")
        if target.offset:
            logger.info(f"Offset is already set ({hex(target.offset)})")
            return target.offset
        logger.info('Looking for the offset')
        logger.info('Starting up the debugger...')
        proc = gdb.debug(target.file.path, api=True)
        debugger = proc.gdb
        sighandler_done = threading.Event()
        logger.info(f'Setting up signal callback')
        debugger.events.stop.connect(_signal_handler)
        debugger.continue_nowait()
        if isinstance(target.pwn_target, CustomOffsetFinderMixin):
            logger.info(f"Using a custom offset finder for {target.pwn_target.__class__.__name__}")
            target.pwn_target.find_offset(proc, debugger, max_offset)
        else:
            cls._find_offset(target, proc, debugger, max_offset)
        if not sighandler_done.wait(timeout=cls.thread_timeout):
            logger.critical("Failed to trigger overflow")
        logger.info("Cleaning up gdb")
        try:
            debugger.execute('c')
        except gdb.error:
            pass
        finally:
            proc.kill()
            proc.close()
            debugger.quit()
            if not target.offset:
                exit(0)

    @classmethod
    def _find_offset(cls, target: TargetBase, proc: pwnlib.tubes.process, _: pwnlib.gdb.Gdb, max_offset: int):
        logger.info(f'Generating payload, size={hex(max_offset)}')
        payload = cyclic(max_offset)
        logger.info(f'Running main...')
        target.pwn_target.main(proc, payload, pwn_target=target.pwn_target)
