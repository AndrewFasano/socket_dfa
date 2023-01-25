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
        for raw_event, next_event in zip(raw_trace, raw_trace[1:] + [None]):
            if event := self.parse_event(raw_event, next_event):
                #print(event)
                self.events.append(event)


    def parse_event(self, raw_line, next_event, interrupted=False):
        line = raw_line.strip()
        if isinstance(raw_line, bytes):
            line = raw_line.strip().decode(errors='ignore')

        # [77f21c6c] _newselect(5, [3 4], NULL, NULL, {0, 987299}) = 1 (in [3], left {0, 984979})'
        # [pid  8680] time([1672158296]) = 1672158296'

        if m := re.match(r'(?:\[pid\s*(\d*)\] )?([a-zA-Z0-9_\\\.]*)\((.*)\)\s+=\s*(-?(?:0x)?[0-9a-f]*)\s?(.*)?', line):
            (pid, sc_name, details, retval, message) = m.groups()
            pid = int(pid) if pid is not None else None

            if details.strip().endswith(")"):
                details = details.strip()[:-1]
            else:
                #self.logger.info(f"Unexpected details without close paren: {details}") # It happens for long lines
                pass

            # This is unfortunately complicated. Woo
            details_s = details

            # Extract {} strings, replace with tokens, then use regex to split
            # then replace tokens
            curly_depth = 0
            quoted = False
            escaped = False
            decurly  = ''
            curly_strs = []

            if '{' in details_s:

                for idx in range(len(details_s)):
                    if details_s[idx] == '\\':
                        # Next char is an escape
                        escaped = True
                        continue

                    if not escaped and quoted is False and details_s[idx] in "\"'":
                        # Saw an unescaped starting quote
                        quoted = details_s[idx]
                    elif not escaped and quoted and details_s[idx] == quoted:
                        # Saw an unescaped, ending quote
                        quoted = False

                    if details_s[idx] == '{':
                        if curly_depth == 0:
                            decurly += f'<CURL>{len(curly_strs)}<ENDCURL>'
                            curly_strs.append('')

                        curly_depth += 1

                    if curly_depth == 0:
                        decurly += details_s[idx]
                    else:
                        curly_strs[-1] += details_s[idx]

                    if details_s[idx] == '}':
                        curly_depth -= 1


                    if escaped:
                        escaped = False

            else:
                decurly = details_s

            # Split with regex
            details = re.findall(r'\[.+?\]|".+?"|\w+', decurly)

            if len(curly_strs):
                # If we have curly strs, replace tokens with the values
                for idx in range(len(details)):
                    while "<CURL>" in details[idx]:
                        post_curl = int(details[idx].split("<CURL>")[1].split("<ENDCURL>")[0])
                        details[idx] = details[idx][:details[idx].index("<CURL>")] + \
                                       curly_strs[post_curl] + \
                                       details[idx][details[idx].index("<ENDCURL>")+9:]

            assert("__CURLY" not in str(details)), f"{raw_line}\n{details}\n\tcontains CURLY"
            for idx in range(len(details)):
                if idx == 1 and details[idx].startswith("\"\\\\177ELF"):
                    details[1] = "[elf_binary]"

                if len(details[idx]) and details[idx][0] == '"' and details[idx][-1] == '"':
                    # Strip quotes on strings since we're storing everything as strings already
                    details[idx] = details[idx][1:-1]

            return TraceLine(pid=pid, syscall_name=sc_name, syscall_args=details, retval=retval,
                                message=message)

        # Line didn't match regex. Need to handle some special cases

        # termination because of our input
        if line.endswith("q"):
            # This is probably when we typed q - i.e., after we're done with analysis
            # but we'll end up doing a q\n in the middle of our line. Unlike with self.interrupted
            # this output isn't pid specific, it's just the next line we want

            # Check if setting prefix will work out with the next line
            if len(line) > 1:
                if next_event:
                    self.prefix = line[:-1] # Just drop the q

                    next_parse = self.parse_event(next_event, None)
                    if next_parse != None and next_parse.special == '':
                        # With prefix we can parse the next line successfully
                        # It can't be a special, if it is we'd parse like Syscall(...q plus Process X detached as a detached
                        return None # Prefix will work, we're good - next line will turn into object

                # Prefix doesn't work, let's hack up this line and recurse
                # on the junk we make
                # Try to recurse, replace the end of the line with something sane
                self.prefix = ""
                newline = line[:-1]

                newline = newline.strip()
                if newline.endswith(","):
                    newline = newline[:-1] # Drop final , since we don't know future args

                if len(line.split("(")) > len(line.split(")")):
                    newline += ")"

                if " = " not in newline:
                    newline += " = 0"
                #print(line, "===>", newline)
                t = self.parse_event(newline, next_event)
                if t is not None:
                    t.special = 'final'
                return t

            return None
        
        # If we had a prefix and the line didn't match, let's retry with prefix
        # if this fails the first match, we'll fall through to the other special cases below
        if len(self.prefix) and not line.startswith("["):
            # Had interrupted data on last parsed line, restore it now
            line = self.prefix + line
            self.prefix = ""
            return self.parse_event(line, next_event)


        # Try to get PID
        pid = None
        if m := re.match(r'(?:\[pid\s*(\d*)\] )?', line):
            pid = m.groups()[0]
            pid = int(pid) if pid is not None else None

        # No PID, if we just had a line break let's assume continuation?
        if pid is None and self.last_pid is not None and self.last_pid in self.interrupted:
            new_line = self.interrupted[self.last_pid].strip() + line # XXX strip is changing data but easier than matching multiline regex
            del self.interrupted[self.last_pid]
            self.last_pid = None
            return self.parse_event(new_line, next_event, interrupted=False)

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
        if m := re.match(r'(?:\[pid\s*(\d*)\] )?<\.\.\. ([a-zA-Z0-9_]*) resumed> (.*)', line): # <... SYSX resumed>
            pid, sc_match, line_end = m.groups()
            pid = int(pid) if pid is not None else None

            if pid not in self.interrupted:
                print(f"WARN: resuming but we missed stop: pid: {pid}, line: {line}")
                return None # XXX TODO - for now ignore...

            new_line = self.interrupted[pid] + line_end
            if ",  " in new_line:
                new_line = new_line.replace(",  ", ", ")
            del self.interrupted[pid]
            return self.parse_event(new_line, next_event, interrupted=True)
        
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
        sc_name = None
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


        #self.logger.warning(f"Unexpected line: {line}")
        print(f"Unexpected line: {line}")
        return None
