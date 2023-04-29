import sys
from loguru import logger as _logger


logger_format = (
    "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | "
    "<level>{level: <8}</level> | "
    "<cyan>[{extra[scope]}]</cyan>:"
    "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> | "
    "<level>{message}</level>"
)
_logger.remove()  # All configured handlers are removed
_logger.add(sys.stderr, format=logger_format, filter=lambda record: not "app" in record["extra"])

_custom_app_logging = (
    "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | "
    "<cyan>[{extra[scope]}]</cyan>:\n"
    "{message}"
)
_custom_app_logger = _logger.bind(app=True)
_custom_app_logger.add(sys.stdout, format=_custom_app_logging, filter=lambda record: "app" in record["extra"])


class classproperty:
    def __init__(self, method=None):
        self.fget = method

    def __get__(self, instance, cls=None):
        return self.fget(cls)

    def getter(self, method):
        self.fget = method
        return self


class LoggableModule:
    @classproperty
    def logger(cls):
        return _logger.bind(scope=cls.__name__)


class LoggableApp:
    @classproperty
    def logger(cls):
        return _custom_app_logger.bind(scope=cls.__name__)

