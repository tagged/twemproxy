#!/bin/bash -xeu

if [[ $# == 0 ]]; then
	echo "Usage: $0 test_a [test_b, ...]" 1>&2
	exit 1
fi

# Print test logging to stderr
export T_LOGFILE=-

if which python3.6 > /dev/null; then
	python3.6 -m nose -v --nologcapture --nocapture "$@"
else
	python3 -m nose -v --nologcapture --nocapture "$@"
fi
