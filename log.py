import logging
import datetime

from pathlib import Path
from rich.logging import RichHandler
from logging.handlers import TimedRotatingFileHandler


# 日志管理类
class Logger:
    """
    日志管理类，支持控制台和文件日志
    """

    def __init__(self, name: str):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)  # 设置为 DEBUG 以捕获所有级别的日志

        # 避免重复添加处理器
        if not self.logger.hasHandlers():
            log_dir = Path(__file__).parent / "logs"
            log_dir.mkdir(parents=True, exist_ok=True)
            log_file_name = f"{name}-{datetime.datetime.now():%Y-%m-%d-%H-%M-%S}.log"
            log_file = log_dir / log_file_name

            # 控制台处理器只显示 INFO 及以上级别
            ch = RichHandler(
                show_time=False,
                show_level=True,
                show_path=False,
                rich_tracebacks=True,
            )
            ch.setLevel(logging.WARNING)  # 控制台只显示 Warning 及以上级别

            # 文件处理器记录所有级别的日志
            fh = TimedRotatingFileHandler(
                log_file, when="midnight", interval=1, backupCount=99, encoding="utf-8"
            )
            fh.setLevel(logging.DEBUG)  # 文件记录 DEBUG 及以上级别
            fh.setFormatter(
                logging.Formatter(
                    "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
                )
            )

            self.logger.addHandler(ch)
            self.logger.addHandler(fh)

    def get_logger(self):
        return self.logger


logger = Logger("ollama").get_logger()
