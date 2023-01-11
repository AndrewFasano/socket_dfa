#!/usr/bin/env python3

import logging
import coloredlogs
import tempfile
import subprocess
import socket
import errno
import os
import time
import re
import copy
import pickle

import glob
from sys import argv
from utils import Trace


def populate_map(results_root):
    bin_trace_map = {} # binary -> [(input_data, trace)]

    for fw_root in glob.glob(f"{results_root}/*/*/traces/"):
        fw_name = fw_root.split("/")[-2].split(".results")[0]
        for trace_dir in glob.glob(f"{fw_root}/*"):
            target_id = trace_dir.split("/")[-1]
            print(fw_name, fw_root, target_id)

            target_binary = open(f"{trace_dir}/filepath.txt").read()
            if target_binary not in bin_trace_map:
                bin_trace_map[target_binary] = []

            for trace in glob.glob(f"{trace_dir}/trace.*"):
                input_data = open(trace.replace("trace.", "input."), "rb").read()
                with open(trace, "rb") as f:
                    t = Trace(input_data, f.read().splitlines())
                bin_trace_map[target_binary].append((input_data, t.events))

    return bin_trace_map

def main(results_root):
    bin_trace_map = populate_map(results_root)

    with open('traces.pickle', 'wb') as f:
        pickle.dump(bin_trace_map, f)

if __name__ == '__main__':
    if len(argv) < 2:
        raise ValueError(f"USAGE: {argv[0]} [results_root]")

    # results/1/RE450_V2_171220.zip.results/traces/
    main(argv[1])
