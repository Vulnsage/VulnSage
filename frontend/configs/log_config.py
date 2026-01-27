import logging


def init_log_config():
    logger = logging.getLogger()
    logger.setLevel('INFO')
    BASIC_FORMAT = "%(asctime)s.%(msecs)d %(levelname)s %(name)s --- %(message)s"
    DATE_FORMAT = '%Y-%m-%d %H:%M:%S'
    formatter = logging.Formatter(BASIC_FORMAT, DATE_FORMAT)
    chlr = logging.StreamHandler()  
    chlr.setFormatter(formatter)
    chlr.setLevel('INFO')
    logger.addHandler(chlr)
