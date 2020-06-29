#! /bin/bash

# Shamelessly stolen from StackOverflow
dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

protoc -I=${dir} --python_out=${dir} ${dir}/panda_messages.proto
