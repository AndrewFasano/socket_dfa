import pickle
import re
from sys import stderr
from copy import copy
from utils import RawTraceLine

target_fw = None
#target_fw = './results/1/DIR-505_FIRMWARE_1.08B10.ZIP.results/traces/3/trace.0'

def s(t):
    '''stringify a trace'''
    if t.special:
        return f"PID {t.pid if t.pid else '-': <8}\t{t.special} {t.syscall_name}({t.syscall_args})"
    return f"PID {t.pid if t.pid else '-': <8}\t{t.syscall_name: >10}({t.syscall_args}) => {t.retval}"

target_scs = [
        "_newselect",
        "recvfrom", "recvmsg", "recv", "read",
        "sendto", "sendmsg", "send", "write",
        "accept", "accept4",
        "fork", "clone",
        "bind",
        "dup2",
        "socket", "poll", "epoll_wait", "epoll_pwait", "epoll_ctl",
        "shutdown", "close", "exit",
        #"rt_sigaction", # Suspend?
        ]
logged=set()

def dprint(*args, **kwargs):
    if target_fw is not None:
        print(*args, *kwargs)

class Despecialize:
    def __init__(self, trace):
        '''
        Given a Trace object, turn it into a more generic representation of what's going on
        or nothing if we don't care
        '''

        # Select, poll, epoll take in 1+ input sockets and decide if any are ready
        self.input_sockets = []
        self.input_sockets_ready = False
        self.input_sockets_has_timeout = False # Is a timeout specified?

        # for IO record buffer as bytes
        self.buffer = None 

        # sendto, write output to a socket
        self.output_socket = None

        # recvfrom, read input from a socket
        self.consume_socket = None
        self.consume_maxlen = None

        # fork / clone: child PID
        self.child_pid = None

        # Accept
        self.accepted = False
        self.accept_child = None

        # Exit. Or maybe close of target sock?
        self.finished = False

        if f := getattr(self, f"handle_{trace.syscall_name}", None):
            try:
                f(trace)
            except (ValueError, IndexError) as e:
                print(f"Failed to parse {trace}: {e}", file=stderr)
        else:
            raise NotImplementedError(f"No despecialization for {trace.syscall_name}")

    def handle__newselect(self, trace):
        # XXX: double underscore because syscall name is '_newselect'
        # SELECT: set input_sockets and input_sockets_ready

        # select takes in one or more FDs
        if len(trace.syscall_args) > 1:
            self.input_sockets = self.destr_sock(trace.syscall_args[1])

        self.input_sockets_ready = (trace.retval != 0)

        if len(trace.syscall_args) > 4:
            self.input_sockets_has_timeout = (trace.syscall_args[4] != "NULL")

    def handle_poll(self, trace):
        # Poll has an FD and direction - we just care about POLLIN
        # may have multiple {fd=1, events=POLLIN}, terms
        target_info = trace.syscall_args[0].split("}, ")
        for target in target_info:
            if m := re.match('\[{fd=(\d*), events=([A-Z]*)', target):
                fd, events = m.groups()
                if events != 'POLLIN':
                    continue
                self.input_sockets.append(int(fd))

        self.input_sockets_ready = (trace.retval != 0)
        self.input_sockets_has_timeout = (trace.syscall_args[2] != "NULL")

    def handle_accept(self, trace):
        self.accepted = True
        self.input_sockets = self.destr_sock(trace.syscall_args[0])
        if trace.retval >= 0:
            self.accept_child = trace.retval

    def handle_recvfrom(self, trace):
        if len(trace.syscall_args) > 0:
            self.consume_socket = self.destr_sock(trace.syscall_args[0])[0]

        if len(trace.syscall_args) > 1:
            self.buffer, self.buffer_truncated = self.destr_buf(trace.syscall_args[1])

        if len(trace.syscall_args) > 2:
            self.consume_maxlen = self.destr_sock(trace.syscall_args[2])[0] # Not a socket but eh

    def handle_recv(self, trace):
        if len(trace.syscall_args) > 1:
            self.consume_socket = self.destr_sock(trace.syscall_args[0])[0]

        if len(trace.syscall_args) > 2:
            self.buffer, self.buffer_truncated = self.destr_buf(trace.syscall_args[1])

        if len(trace.syscall_args) > 3:
            self.consume_maxlen = self.destr_sock(trace.syscall_args[2])[0] # Not a socket but eh

    def handle_recvmsg(self, trace):
        self.consume_socket = self.destr_sock(trace.syscall_args[0])[0]

        if "msg_iov(1)=[" not in trace.syscall_args[1]:
            raise NotImplementedError() # Don't wanna deal

        iov = trace.syscall_args[1].split('msg_iov(1)=[{')[1].split("}")[0]
        self.buffer, self.buffer_truncated = self.destr_buf(iov)
        #self.consume_maxlen = self.destr_sock(trace.syscall_args[2]) # Not a socket but eh

    def handle_read(self, trace):
        self.consume_socket = self.destr_sock(trace.syscall_args[0])[0]
        self.buffer, self.buffer_truncated = self.destr_buf(trace.syscall_args[1])

        if len(trace.syscall_args) > 2:
            self.consume_maxlen = self.destr_sock(trace.syscall_args[2])[0] # Not a socket but eh
        # Could check if rv > len and truncate?

    def handle_sendto(self, trace):
        # SENDTO: set output_socket and buffer
        if len(trace.syscall_args) > 1:
            self.output_socket = self.destr_sock(trace.syscall_args[0])[0]

        if len(trace.syscall_args) > 2:
            self.buffer, self.buffer_truncated = self.destr_buf(trace.syscall_args[1])

    def handle_write(self, trace):
        if len(trace.syscall_args) > 1:
            self.output_socket = self.destr_sock(trace.syscall_args[0])[0]

        if len(trace.syscall_args) > 2:
            self.buffer, self.buffer_truncated = self.destr_buf(trace.syscall_args[1])

    def handle_fork(self, trace):
        if trace.retval >= 0:
            self.child_pid = trace.retval

    def handle_clone(self, trace):
        if trace.retval >= 0:
            self.child_pid = trace.retval

    def handle_exit(self, trace):
        self.finished = True

    def __str__(self):
        if self.accepted:
            # Did we just accept
            return f"Accepted to get {self.accept_child} from {self.input_sockets[0]}"

        if len(self.input_sockets):
            # Did we just mark a socket as ready/not
            if self.input_sockets_ready:
                return f"checking if data on {self.input_sockets}: ready"
            return f"checking if data on {self.input_sockets}: not ready"

        if self.finished:
            return f"Finished"

        if self.consume_socket:
            # Did we just consume?
            return f"consuming {self.buffer} from {self.consume_socket}"

        if self.output_socket:
            # Did we just send?
            return f"sending {self.buffer} to {self.output_socket}"

        if self.child_pid:
            return f"created child {self.child_pid}"

        return ""

    @staticmethod
    def destr_buf(buf):
        truncated = False
        # buffers are sometimes quoted. May have octal escaped bytes with \\. May end with ...

        _quoted = False
        if buf.startswith('"'):
            _quoted = True
            buf = buf[1:]

        if buf.endswith('...'):
            truncated = True
            assert(_quoted) # Assuming only quoted strings can end with ..., drop the quotes here
            _quoted = False
            buf = buf[:-4] # Trim off the four chars for "... at end. There's no non-quoted ... ending

        if _quoted:
            buf = buf[:-1]

        result = [] # list of ints
        idx = 0
        oct_str = '01234567'
        while idx < len(buf):
            if buf[idx] == '\\':
                # Read 1-3 chars. End at EOF or non 0-8 char
                oct_bytes = ''

                for oct_idx in range(idx+1, min(idx+4, len(buf))):
                    # First byte is *always* added, e.g., \t or \n. 
                    if oct_idx != idx+1 and buf[oct_idx] not in oct_str:
                        break

                    oct_bytes += buf[oct_idx]

                    # If we just added a first byte and it's a special char, bail now
                    if oct_idx == idx+1 and oct_bytes[0] not in oct_str:
                        break

                # It might be a special character such as \t or an octal val like 1

                if len(oct_bytes):
                    if not oct_bytes.isnumeric():
                        # Here we have special chars from strace like "t" for \t, need to ord it by hand
                        val = { 'a': 0x07,
                                'b': 0x08,
                                't': 0x09,
                                'n': 0x0A,
                                'v': 0x0B,
                                'f': 0x0C,
                                'r': 0x0D,
                                # We can also have an escaped quote in a quoted string:
                                '\\': ord("\\"),
                                '"': ord('"'),
                                }[oct_bytes]
                        result.append(val)


                    else:
                        result.append(int(oct_bytes, 8)) # oct str ->  int

                idx += len(oct_bytes) # Shift past the octal buffer
            else:
                result.append(ord(buf[idx]))

            idx += 1

        return bytes(result), truncated

    @staticmethod
    def destr_sock(s):
        if s.startswith("[") and s.endswith("]"):
            # [1, 2] or [1]
            nums = s[1:-1].split(" ") # It's a list 
            return [int(x) for x in nums]
        elif s.startswith("["):
            raise NotImplementedError(f"unterminated list: {s}")
        else:
            # Not a list, should just be a number
            if s == 'NULL':
                # But let's also support null
                return None
            else:
                return [int(s)]

def should_ignore(t, warn=False):
    if t.syscall_name not in target_scs:
        if t.syscall_name not in logged:
            if warn:
                print("IGNORING:", t.syscall_name)
            logged.add(t.syscall_name)
        return True

def track_sock_state(t, idx, active_pids, observed_pids, parent_to_children):
    '''
    Track socket state across processes by examining syscalls.
    Note we shouldn't really need to do this when using kernel assistance
    '''

    if t.pid not in active_pids:
        # First syscall seen in PID
        active_pids[t.pid] = {'socks': {}}

    if t.pid not in observed_pids:
        observed_pids[t.pid] = [[]]

    if t.pid not in parent_to_children:
        parent_to_children[t.pid] =  [] # Simple parent pid ->child pid mapping

    # In each active_pid, track a list of (idx, syscall)s
    observed_pids[t.pid][-1].append((idx, t))

    '''
    if t.syscall_name == 'close':
        # This isn't a Despecialize-able syscall since we don't care there
        fd = int(t.syscall_args[0])
        if fd in active_pids[t.pid]['socks']:
            #del active_pids[t.pid]['socks'][fd]
            active_pids[t.pid]['socks'][fd]['closed'] = True
    '''

    # update t.pid[socks] for various syscalls
    # key is sock FD, properties should include blocking/non?
    try:
        d = Despecialize(t)
    except NotImplementedError:
        return
    except Exception as e:
        print("Failed to despecialize:", t)
        raise

    # If we just saw some sockets, make sure they exist in the current PID
    for sock in d.input_sockets:
        if sock not in active_pids[t.pid]['socks']:
            active_pids[t.pid]['socks'][sock] = {'children': [], 'parent': None, 'inp_parent': False, 'inp': False}

    if d.accept_child:
        # We just accepted - the current socket now has a child
        input_sock = d.input_sockets[0]
        # input_sock must be in socks map already, so just update children
        active_pids[t.pid]['socks'][input_sock]['children'].append(d.accept_child)
        #print(f"Set child for " + \
        #      f"{active_pids[t.pid]['socks'][input_sock]} with {d}, {t}")

        # Now create the child and set its parent
        if d.accept_child in active_pids[t.pid]['socks']:
            print("Child already existed!") # XXX what?
            active_pids[t.pid]['socks'][d.accept_child]['parent'] = input_sock
        else:
            active_pids[t.pid]['socks'][d.accept_child] = { 'children': [],
                                                            'parent': input_sock,
                                                            'inp_parent':False,
                                                            'inp': False}

    if d.child_pid:
        # We forked, copy sockets into child process
        parent_to_children[t.pid].append(d.child_pid)
        active_pids[d.child_pid] = {'socks': copy(active_pids[t.pid])}


    if d.finished:
        # Last syscall, delete pending trace
        del active_pids[t.pid]
        observed_pids[t.pid].append([]) # If we see this PID again, it's a new process

def run_algo(t, t_idx, active_pids, parent_to_children, algo_state):
    try:
        dsp = Despecialize(t)
    except NotImplementedError:
        dprint(f'> {t_idx: >3}, {s(t)}')
        return (False, None)

    dprint(f'>> {t_idx: >3}, {s(t)}')

    # using active_pids and parent_to_children we should be able to examine sock details

    if dsp.accepted:
        accept_sock = dsp.input_sockets[0] if len(dsp.input_sockets) else None

        if t.pid in active_pids and accept_sock in active_pids[t.pid]['socks']:
            sock_state = active_pids[t.pid]['socks'][accept_sock]
            if sock_state['inp_parent']:
                sc_cnt = t_idx - algo_state['start_ctr']
                return (sc_cnt, 'accept_parent')


    elif len(dsp.input_sockets):
        for sock in dsp.input_sockets:
            if t.pid in active_pids and sock in active_pids[t.pid]['socks']:
                sock_state = active_pids[t.pid]['socks'][sock]
                if not sock_state['inp']:
                    continue
                # We just did a select on something that we've already provided input on
                # If we've provided all the input, we should be done now
                if len(algo_state['input_data']) == 0:
                    sc_cnt = t_idx - algo_state['start_ctr']
                    return (sc_cnt, 'select')

    if dsp.consume_socket is not None:
        is_recv = dsp.buffer is not None \
                        and len(algo_state['input_data']) \
                        and dsp.consume_maxlen is not None \
                        and dsp.buffer.startswith(algo_state['input_data'][:min(50, dsp.consume_maxlen)])


        # If we already read input_buffer from this socket and have none left, we might be done.
        # Note we don't currently use this!
        is_recv_eom = len(algo_state['input_data']) == 0 \
                      and t.pid in active_pids \
                      and dsp.consume_socket in active_pids[t.pid]['socks'] \
                      and active_pids[t.pid]['socks'][dsp.consume_socket]['inp']

        
        if is_recv_eom:
            active_pids[t.pid]['consumed_input'] = True # This PID consumed the whole input!

        if is_recv:
            # Guest read some amount of input_data (from VPN), replace it with real data
            # update algo_state.
            if not algo_state['input_pending']:
                # First input: update state for socket/parent
                algo_state['input_pending'] = t.pid

                # TODO: analyze active_pids, parent_to_children to figure out what's up
                # with our sockets!
                
                # Looking for dsp.consume_socket in active_pids[t.pid]

                if dsp.consume_socket not in  active_pids[t.pid]['socks']:
                    active_pids[t.pid]['socks'][dsp.consume_socket] = { 'children': [], 'parent': None, 'inp': False, 'inp_parent': False}

                sock = active_pids[t.pid]['socks'][dsp.consume_socket]
                sock['inp'] = True
                sock['timeout_ctr'] = 0

                algo_state['start_ctr'] = t_idx
                #print(f"Start processing at {t_idx} on sock {dsp.consume_socket}:", sock, t)
                if sock['parent'] is not None:
                    #print(active_pids[t.pid]['socks'][sock['parent']])
                    active_pids[t.pid]['socks'][sock['parent']]['inp_parent'] = True


            # How long was *actually* read from real data vs how much do we simulate reading here
            real_buf_len = min(dsp.consume_maxlen, len(algo_state['input_data']))
            buf_len = min(dsp.consume_maxlen,
                            len(algo_state['fuzz_buffer'][algo_state['fuzz_buffer_idx']:]))

            # XXX: In real use, we'd now need to write our buffer into guest memory
            # For now we just log it
            fuzz_idx = algo_state['fuzz_buffer_idx']
            payload = algo_state['fuzz_buffer'][fuzz_idx:fuzz_idx+buf_len]
            #print(f"Write {payload} into guest memory at this recv")

            # Update position in fuzz buffer
            algo_state['fuzz_buffer_idx'] += buf_len

            # Update input_data for partial reads so we can identify next read.
            algo_state['input_data'] = algo_state['input_data'][real_buf_len:]
            #dprint(f"Input len now: {len(algo_state['input_data'])} after read of {real_buf_len}")


            # Have we now consumed the full original buffer? If so we're done consuming input?
            # But the target might only consume *some*
            if len(algo_state['input_data']) == 0:
                active_pids[t.pid]['consumed_input'] = True # This PID consumed the whole input!

    finished = False
    if algo_state['input_pending'] is not False:
        sc_cnt = t_idx - algo_state['start_ctr']
        if t.pid == algo_state['input_pending']:
            # The process that did the recv now accepts or exits
            if dsp.finished:
                # A process is existing - could this be the end?
                # It's the end of the existing PID is the one that recv'd
                #print(f"Finish after {sc_cnt} syscalls: Exit in {t.pid} after recv in {algo_state['input_pending']}")
                return (sc_cnt, 'exit')

            if dsp.input_sockets:
                # A process does a select again - could this be the end?
                for sock_fd in dsp.input_sockets:
                    sock = active_pids[t.pid]['socks'][sock_fd]

                    if hasattr(sock, 'timeout_ctr'):
                        # If there's a timeout, let's make it timeout twice, once to see
                        # end if input (and hopefully process) and another is gonna be a loop
                        # If a select/poll has a timeout and it did timeout, increment counter
                        # XXX is this bad? It might be, it will add one timeout period to end...
                        if dsp.input_sockets_has_timeout and not dsp.input_sockets_ready:
                            sock['timeout_ctr'] += 1
                    #else:
                        # This isn't the sock that we saw the input recv'd on
                        #continue

                    # If there's more pending data that we haven't yet consumed, it's not done!
                    if len(algo_state['input_data']) == 0 and \
                                not (hasattr(sock, 'timeout_ctr') and \
                                     dsp.input_sockets_has_timeout and sock['timeout_ctr'] < 2):
                        # It is if the process selecting did the recv?
                        #print(f"Finish after {sc_cnt} syscalls: Select in {t.pid} after recv in {algo_state['input_pending']}")
                        return (sc_cnt, 'select')
        else:
            # Do we do anything here with a different PID when we have input?
            pass

    return (False, None)


def analyze(fw, binary, input_data, trace_list):
    # For a given input, we have an ordered list of RawTraceLines

    active_pids = {} # pid -> syscall. Note None is a valid PID, for the original target
    observed_pids = {}

    # Children of PIDs. Tree. None is root. If we have
    # [None: [1], 1: [2,3] 2: [], 3:[]] that means root made 1, and 1 made 2+3
    # List of child PIDS
    parent_to_children = {None: []}
    idx = 0
    input_recvs = [] # sc_idx of recv

    # input_data is the buffer we actually sent
    # fuzz_buffer is the buffer we want to place into memory
    # for testing it's the same, later we'll change.
    # note len(fuzz_buffer) should be <= len(input_data
    algo_state = {
            'input_pending': False,
            'input_data': input_data,
            'fuzz_buffer': input_data,
            'fuzz_buffer_idx': 0
            }


    # For every trace item, despecialize it.
    # Also do some (just for testing) process tree analysis
    # so we can track FDs between processes. Maybe
    finished = False
    for t in trace_list:

        # Ignore blank syscall objects (first line is sometimes blank)
        if not len(t.syscall_name):
            continue

        if should_ignore(t, warn=False):
            continue

        # Ensure retvals are always numeric
        if t.retval.isnumeric():
            t.retval = int(t.retval)
        else:
            t.retval = 0 # I guess?

        # Manage PID trace and parent->child maps. Maybe unnecessary with kernel assitance?
        track_sock_state(t, idx, active_pids, observed_pids, parent_to_children)

        # Run algo. Input trace element, input_data, current PID trace and parent->child maps
        #if not finished:
        (finished, finish_reason) = run_algo(t, idx, active_pids, parent_to_children, algo_state)
        if finished is not False: # Will be an int of number of scs from start to finish
            break

        idx += 1

    if finished:
        print(f"{fw}, {binary}, {str(input_data[:10])[2:-1]}, {finished}, {finish_reason}")
    else:
        print(f"{fw}, {binary}, {str(input_data[:10])[2:-1]}, unfinished,")

def main(bin_trace_map):
    # Trace map is {bin_a: [(input1, [trace_of_input_1], ...)], bin_b: ...}

    # BUT: we might have the same inputs in our list for a binary IFF that binary
    # bound in multiple ways (i.e.: tcp + udp, two ports)
    for binary, data in bin_trace_map.items():
        if binary.endswith("/vpn"):
            continue

        total_trace_lines = sum([len(trace_list) for _, _, trace_list in data])
        if total_trace_lines < len(data)*2:
            print(f"----- Skipping {binary} since we saw just {total_trace_lines} syscalls for " + \
                  f"for {len(data)} inputs", file=stderr)
            continue

        for (fw, input_data, trace_list) in data:
            if target_fw is not None and fw != target_fw:
                continue
            try:
                analyze(fw, binary, input_data, trace_list)
            except Exception as e:
                print(f"ERROR processing", fw)
                raise

if __name__ == '__main__':
    with open("traces.pickle", "rb") as f:
        main(pickle.load(f))
