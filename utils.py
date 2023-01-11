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

from dataclasses import dataclass, field
from typing import Any, List

@dataclass
class RawTraceLine:
    pid: int
    syscall_name: str
    syscall_args: List[str]
    retval: int
    message: str
    special: str # If set, args in syscall_args

    # Valid specials: exit(code), detached, signal (signal, CLD_XXX, PID)

def TraceLine(pid=None, syscall_name=None, syscall_args=None, retval=None, message=None, special=None):
    if syscall_name is None:
        syscall_name = ""
    if syscall_args is None:
        syscall_args = []
    if message is None:
        message = ""
    if special is None:
        special = ""
    return RawTraceLine(pid=pid, syscall_name=syscall_name, syscall_args=syscall_args, retval=retval, message=message, special=special)

@dataclass(order=True)
class PrioritizedItem:
    priority: int
    item: Any=field(compare=False)

class Trace:
    def __init__(self, input_data, raw_trace):
        '''
        A class to represent a trace of a program. Initialized with a raw text trace
        of a program, which is then converted into meaningful information including
            Unique PCs
            Event (i.e. syscall) names
            Event details

            input_data + raw_traces are bytestrings
        '''
        self.input_data = input_data
        self.events = [] # List of RawTraceLine objects
        self.logger = logging.getLogger("trace_parser")

        self.interrupted = {} # pid -> interrupted line
        self.last_pid = None # If there was a linebreak record the last PID we saw. 0 means NA but not None

        self.prefix = ""
        for raw_event in raw_trace:
            if event := self.parse_event(raw_event):
                self.events.append(event)


    def parse_event(self, raw_line, interrupted=False):
        line = raw_line.strip()
        if isinstance(raw_line, bytes):
            line = raw_line.strip().decode(errors='ignore')

        # [77f21c6c] _newselect(5, [3 4], NULL, NULL, {0, 987299}) = 1 (in [3], left {0, 984979})'
        # [pid  8680] time([1672158296]) = 1672158296'

        if m := re.match(r'(?:\[pid\s*(\d*)\] )?([a-zA-Z0-9_\\\.]*)\((.*)\s+=\s*(-?(?:0x)?[0-9a-f]*)\s?(.*)?', line):
            (pid, sc_name, details, retval, message) = m.groups()
            pid = int(pid) if pid is not None else None

            if details.strip().endswith(")"):
                details = details.strip()[:-1]
            else:
                #self.logger.info(f"Unexpected details without close paren: {details}") # It happens for long lines
                pass
            details = details.split(", ")


            for idx in range(len(details)):
                if idx == 1 and details[idx].startswith("\"\\\\177ELF"):
                    details[1] = "[elf_binary]"

                if len(details[idx]) and details[idx][0] == '"' and details[idx][-1] == '"':
                    # Strip quotes on strings since we're storing everything as strings already
                    details[idx] = details[idx][1:-1]

            return TraceLine(pid=pid, syscall_name=sc_name, syscall_args=details, retval=retval,
                                message=message)

        # Line didn't match regex. Need to handle some special cases
        
        # If we had a prefix and the line didn't match, let's retry with prefix
        # if this fails the first match, we'll fall through to the other special cases below
        if len(self.prefix) and not line.startswith("["):
            # Had interrupted data on last parsed line, restore it now
            line = self.prefix + line
            self.prefix = ""
            return self.parse_event(line)


        # Try to get PID
        pid = None
        if m := re.match(r'(?:\[pid\s*(\d*)\] )?', line):
            pid = m.groups()[0]
            pid = int(pid) if pid is not None else None

        # No PID, if we just had a line break let's assume continuation?
        if pid is None and self.last_pid is not None and self.last_pid in self.interrupted:
            new_line = self.interrupted[self.last_pid].strip() + line # XXX strip is changing data but easier than matching multiline regex
            del self.interrupted[pid]
            self.last_pid = None
            return self.parse_event(new_line, interrupted=False)

        elif self.last_pid:
            print("WARN Set last_pid but didn't get a line continuation?")


        # See if it exited
        exit_code = None
        if m := re.match(r'(?:\[pid\s*(\d*)\] )?\+\+\+ exited with (\d*) \+\+\+', line):
            pid, exit_code = m.groups()
            pid = int(pid) if pid is not None else None
            exit_code = int(exit_code) if exit_code is not None else -1
            return TraceLine(pid=pid, special="exit", syscall_args=[exit_code]) # Do we care?

        if line.endswith("<unfinished ...>"):
            if len(line) > len("<unfinished ...>"):
                # Otherwise just ignore the unifinished syscall, it must be junk? or part of one we have
                self.interrupted[pid] = line[:line.index("<unfinished ...>")]
            return None # We'll handle later?

        # Resumed after a prior context-switch mid syscall
        if m := re.match(r'(?:\[pid\s*(\d*)\] )?<\.\.\. ([a-zA-Z0-9_]*) resumed> .*', line): # <... SYSX resumed>
            pid, line_end = m.groups()
            pid = int(pid) if pid is not None else None

            if pid not in self.interrupted:
                print(f"WARN: resuming but we missed stop: pid: {pid}, line: {line}")
                return None # XXX TODO - for now ignore...

            new_line = self.interrupted[pid].strip() + line_end
            del self.interrupted[pid]
            return self.parse_event(new_line, interrupted=True)
        
        # On detach we seem to see Process X detached\n<detached ...> as two lines
        if line.startswith("<detached"):
            return None
        if line.endswith("detached"):
            return TraceLine(pid=pid, special="detach") # Do we care?

        if line.endswith("attached"):
            self.interrupted[pid] = line[:line.index("Process ")] # Process X attached
            return None

        # Might just have a line break in args Maybe just with 'read' and similar syscalls?
        if m := re.match(r'(?:\[pid\s*(\d*)\] )?([a-zA-Z0-9_\\\.]*)\((.*)', line):
            pid, sc_name, details = m.groups()
            pid = int(pid) if pid is not None else 0 # XXX this case is special

            details = details.split(", ") # XXX could be in in input...
            if details[-1].startswith('"') and not \
                    (details[-1].endswith('"') or details[-1].endswith('...')):
                self.last_pid = pid
                self.interrupted[pid] = line
                return None

        # Syscall name shows up twice (Strange, but happens a bunch
        # e.g., epoll_pwait(3,epol_pwait
        if m := re.match(r'(?:\[pid\s*(\d*)\] )?([a-zA-Z0-9_\\\.]*)\(', line):
            pid, sc_name = m.groups()
            if pid is None:
                pid = int(pid) if pid is not None else None

            if line.endswith(sc_name):
                #  This is our weird case. Hmm. Ignore it?
                return None

        if m := re.match(r'--- SIG([A-Z]*) {si_signo=([A-Z]*), si_code=([A-Z_]*), si_pid=(\d*), si_uid=(\d*), si_status=(\d*), si_utime=(\d*), si_stime=(\d*)} ---', line):
            sig, sig2, code, pid, uid, status, utime, stime = m.groups()
            pid = int(pid) if pid is not None else None
            #print("TODO SIGNAL:", sig, sig2, code, pid, uid, status, utime, stime)
            #return None # TODO
            return TraceLine(pid=pid, special="signal", syscall_args=[sig, code, pid]) # Do we care?


        # termination because of our input
        if line.endswith("q"):
            # This is probably when we typed q - i.e., after we're done with analysis
            # but we'll end up doing a q\n in the middle of our line. Unlike with self.interrupted
            # this output isn't pid specific, it's just the next line we want
            if len(line) > 1:
                self.prefix = line[:-1]
                #print("XXX SET PREFIX FOR LINE:", line)
            return None


        #self.logger.warning(f"Unexpected line: {line}")
        print(f"Unexpected line: {line}")
        return None
