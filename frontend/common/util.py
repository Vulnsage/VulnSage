import logging
import re


logger = logging.getLogger(__name__)


def get_last_x_lines(text, line):
    lines = text.strip().split('\n')
    last_x_lines = lines[-line:]
    result = '\n'.join(last_x_lines)
    return result

