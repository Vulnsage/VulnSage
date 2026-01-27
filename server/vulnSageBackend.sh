#!/bin/bash


ROOT_PATH=$(pwd)


FERNFLOWER_PATH="${ROOT_PATH}/extension/fernflower.jar"
LIBTRACE_PATH="${ROOT_PATH}/extension/libtrace_x86_64_linux_jdk1.8.so"
EZJNDI_PATH="${ROOT_PATH}/extension/ezjndi.jar"


export VULN_SAGE_FERNFLOWER_PATH="$FERNFLOWER_PATH"
export VULN_SAGE_LIB_TRACE_PATH="$LIBTRACE_PATH"
export VULN_SAGE_ROOT_PATH="$ROOT_PATH"
export VULN_SAGE_EZJNDI_PATH="$EZJNDI_PATH"


echo "VULN_SAGE_FERNFLOWER_PATH=$FERNFLOWER_PATH"
echo "VULN_SAGE_LIB_TRACE_PATH=$LIBTRACE_PATH"
echo "VULN_SAGE_ROOT_PATH=$ROOT_PATH"
echo "VULN_SAGE_EZJNDI_PATH=$EZJNDI_PATH"


if [ ! -f "$FERNFLOWER_PATH" ]; then
    echo "fernflower.jar not found."
    exit 1
fi
if [ ! -f "$LIBTRACE_PATH" ]; then
    echo "libtrace.so not found."
    exit 1
fi
if [ ! -f "$EZJNDI_PATH" ]; then
    echo "ezjndi.jar not found."
    exit 1
fi


if ! command -v nc &> /dev/null; then
    echo "nc command not found."
    exit 1
fi
if ! command -v nohup &> /dev/null; then
    echo "nohup command not found."
    exit 1
fi


nohup java -jar "$EZJNDI_PATH" -lp=1099 -hp=48080 -c='echo "test_message" | nc localhost 59876' &


chmod +x ./vulnSageBackend
./vulnSageBackend