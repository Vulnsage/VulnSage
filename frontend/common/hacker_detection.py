import logging
import os
import re
import tempfile

from configs import LANGUAGE_NODEJS, LANGUAGE_JAVA, HACKER_PASSED_MESSAGE, LANGUAGE_PYTHON, VULN_TYPE_COMMAND_INJECTION, \
    VULN_TYPE_PROTOTYPE_POLLUTION, VULN_TYPE_CODE_INJECTION, VULN_SAGE_FRONTEND_ROOT_PATH
from .exceptions import LangaugeNotSupported

logger = logging.getLogger(__name__)


def check_code_hacker(script_code: str, vuln_type: str, language: str) -> str:
    
    if language == LANGUAGE_NODEJS:
        return check_nodejs_code_hacker(script_code, vuln_type)
    elif language == LANGUAGE_JAVA:
        return check_java_code_hacker(script_code, vuln_type)
    elif language == LANGUAGE_PYTHON:
        return check_python_code_hacker(script_code, vuln_type)
    else:
        logger.error(f"Unsupported language: {language}")
        raise LangaugeNotSupported(f"{language}")


def check_java_code_hacker(script_code, vuln_type) -> str:
    if vuln_type == "command_injection":
        return check_java_code_hacker_for_command_injection(script_code)
    else:
        logger.info(f"vuln_type: {vuln_type} not set code hacker")
        return HACKER_PASSED_MESSAGE


def check_python_code_hacker(script_code, vuln_type) -> str:
    if vuln_type == VULN_TYPE_COMMAND_INJECTION:
        return check_python_code_hacker_for_command_injection(script_code)
    elif vuln_type == VULN_TYPE_CODE_INJECTION:
        return check_python_code_hacker_for_pickle_injection(script_code)
    else:
        logger.info(f"vuln_type: {vuln_type} not set code hacker")
        return HACKER_PASSED_MESSAGE


NODEJS_CODE_INJECTION_HACKER_ENHANCEMENT = True


def check_nodejs_code_hacker(script_code, vuln_type) -> str:
    if vuln_type == VULN_TYPE_COMMAND_INJECTION:
        return check_nodejs_code_hacker_for_command_injection(script_code)
    elif vuln_type == VULN_TYPE_PROTOTYPE_POLLUTION:
        return check_nodejs_code_hacker_for_prototype_pollution(script_code)
    elif vuln_type == VULN_TYPE_CODE_INJECTION:
        flag = check_nodejs_code_hacker_for_code_injection(script_code)
        if flag != HACKER_PASSED_MESSAGE:
            return flag
        if NODEJS_CODE_INJECTION_HACKER_ENHANCEMENT:
            return check_nodejs_code_hacker_for_code_injection_with_ast_structure(script_code)
    else:
        logger.info(f"vuln_type: {vuln_type} not set code hacker")
        return HACKER_PASSED_MESSAGE
        


def check_python_code_hacker_for_pickle_injection(script_code) -> str:
    patterns = {
        "Forbidden use pickle.loads;": re.compile(r'\bpickle\.loads\b', re.DOTALL | re.IGNORECASE),
        "Forbidden use pickle.load;": re.compile(r'\bpickle\.load\b', re.DOTALL | re.IGNORECASE),
    }
    detected = []
    for tag, pattern in patterns.items():
        if re.search(pattern, script_code):
            detected.append(tag)
    if len(detected) == 0:
        return HACKER_PASSED_MESSAGE
    else:
        detect_result = ";".join(detected)
        return detect_result


def check_python_code_hacker_for_command_injection(script_code) -> str:
    patterns = {
        "Forbidden use os.system;": re.compile(r'\bos\.system\b', re.DOTALL | re.IGNORECASE),
        "Forbidden use os.popen;": re.compile(r'\bos\.popen\b', re.DOTALL | re.IGNORECASE),
        "Forbidden use subprocess.call;": re.compile(r'\bsubprocess\.call\b', re.DOTALL | re.IGNORECASE),
        "Forbidden use subprocess.run;": re.compile(r'\bsubprocess\.run\b', re.DOTALL | re.IGNORECASE),
        "Forbidden use subprocess.Popen;": re.compile(r'\bsubprocess\.Popen\b', re.DOTALL | re.IGNORECASE),
    }
    detected = []
    for tag, pattern in patterns.items():
        if re.search(pattern, script_code):
            detected.append(tag)
    if len(detected) == 0:
        return HACKER_PASSED_MESSAGE
    else:
        detect_result = ";".join(detected)
        return detect_result


def check_nodejs_code_hacker_for_code_injection(script_code) -> str:
    patterns = {
        "Forbidden use toString; use raw string instead": re.compile(r'\btoString\b', re.DOTALL | re.IGNORECASE),
    }
    detected = []
    for tag, pattern in patterns.items():
        if re.search(pattern, script_code):
            detected.append(tag)
    if len(detected) == 0:
        return HACKER_PASSED_MESSAGE
    else:
        detect_result = ";".join(detected)
        return detect_result


import subprocess


def check_nodejs_code_hacker_for_code_injection_with_ast_structure(script_code) -> str:
    checker_path = VULN_SAGE_FRONTEND_ROOT_PATH / "scripts" / "checker"
    checker_file = checker_path / "check.ts"
    if not checker_file.exists():
        logger.error(f"checker_file: {checker_file} not exists")
        return HACKER_PASSED_MESSAGE
    tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".ts")
    with open(tmp_file.name, "w") as f:
        f.write(script_code)
    cmd = f"./node_modules/.bin/ts-node {checker_file} {tmp_file.name}"
    logger.info(f"cmd: {cmd}")
    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=10,
                                         cwd=checker_path)
        logger.info(f"output: {output}")
        os.remove(tmp_file.name)
        output = output.decode("utf-8")
        if "check failed" in output:
            return "Forbidden use a CALLBACK function or a getter function like requre('child_process').exec parameter to achieve it."
    except subprocess.CalledProcessError as e:
        logger.error(f"cmd: {cmd} failed, error: {e}")
        return HACKER_PASSED_MESSAGE


def check_nodejs_code_hacker_for_prototype_pollution(script_code) -> str:
    patterns = {
        "Forbidden use Object.prototype;": re.compile(r'\bObject\.prototype\b', re.DOTALL | re.IGNORECASE),
        "Forbidden use Object.assign;": re.compile(r'\bObject\.assign\b', re.DOTALL | re.IGNORECASE),
        "Forbidden use Object.create;": re.compile(r'\bObject\.create\b', re.DOTALL | re.IGNORECASE),
        "Forbidden use Object.defineProperty;": re.compile(r'\bObject\.defineProperty\b', re.DOTALL | re.IGNORECASE),
        "Forbidden use Object.defineProperties;": re.compile(r'\bObject\.defineProperties\b',
                                                             re.DOTALL | re.IGNORECASE),
        "Forbidden use Object.setPrototypeOf;": re.compile(r'\bObject\.setPrototypeOf\b', re.DOTALL | re.IGNORECASE),
    }
    detected = []
    for tag, pattern in patterns.items():
        if re.search(pattern, script_code):
            detected.append(tag)
    if len(detected) == 0:
        return HACKER_PASSED_MESSAGE
    else:
        detect_result = ";".join(detected)
        return detect_result


def check_nodejs_code_hacker_for_command_injection(script_code) -> str:
    patterns = {
        "Forbidden use toString; use raw string instead": re.compile(r'\btoString\b', re.DOTALL | re.IGNORECASE),
        "Forbidden use child_process;": re.compile(r'\bchild_process\b', re.DOTALL | re.IGNORECASE),
    }
    detected = []
    for tag, pattern in patterns.items():
        if re.search(pattern, script_code):
            detected.append(tag)
    if len(detected) == 0:
        return HACKER_PASSED_MESSAGE
    else:
        detect_result = ";".join(detected)
        return detect_result


def check_java_code_hacker_for_command_injection(script_code) -> str:
    patterns = {
        "Forbidden use createNewFile;": re.compile(r'\bcreateNewFile\b', re.DOTALL | re.IGNORECASE),
        "Forbidden use createFile;": re.compile(r'\bcreateFile\b', re.DOTALL | re.IGNORECASE),
        "Forbidden use ProcessBuilder.start();": re.compile(
            r'\bnew\s+ProcessBuilder\b.*?\.start\(\)|pb\.start|pbuilder\.start', re.DOTALL | re.IGNORECASE),
        "Forbidden use Runtime.getRuntime.exec": re.compile(r'\bRuntime\.getRuntime\(\)\.exec\b',
                                                            re.DOTALL | re.IGNORECASE),
        "Forbidden use FileWriter.write": re.compile(r'\bnew\s+FileWriter\b.*?\.write\(', re.DOTALL | re.IGNORECASE),
    }
    detected = []
    
    for tag, pattern in patterns.items():
        if re.search(pattern, script_code):
            detected.append(tag)
    
    if len(detected) == 0:
        return HACKER_PASSED_MESSAGE
    else:
        detect_result = ";".join(detected)
        return detect_result
