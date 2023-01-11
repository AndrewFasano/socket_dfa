import pickle
from utils import RawTraceLine

def s(t):
    '''stringify a trace'''
    if t.special:
        return f"PID {t.pid if s.pid else '-': <8}\t{t.special}({t.syscall_args})"
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

def stracify_str(input_data):
    '''
    Python  b'\x00\x05AAAAA' convert to strace format:
    strace: \0\5AAAAA

    Also it's in octal so b'\x08' is \10.  And it supports special cahars so b'\x09' is \t. Yikes
    '''
    i = input_data[:8].decode(errors='ignore')
    res = ""

    for c in i:
        if c.isprintable():
            res += c
        else:
            res += "\\"+oct(ord(c))[2:] # Yes, it's in octal

    return res


def analyze(input_data, trace_list):
    # For a given input, we have an ordered list of RawTraceLines

    print("Input: ", input_data[:10])

    active_pids = {} # pid -> syscall. Note None is a valid PID, for the original target

    # Children of PIDs. Tree. None is root. If we have
    # [None: [1], 1: [2,3] 2: [], 3:[]] that means root made 1, and 1 made 2+3
    # List of child PIDS
    parent_to_children = {None: []}
    idx = 0
    input_recvs = [] # sc_idx of recv

    for t in trace_list:
        # Warn on ignored SCs (just for now)
        if t.syscall_name not in target_scs:
            if t.syscall_name not in logged:
                print("IGNORING:", t.syscall_name)
                logged.add(t.syscall_name)
            continue

        # Track PIDs
        if t.pid not in active_pids:
            active_pids[t.pid] = []

        if t.pid not in parent_to_children:
            parent_to_children[t.pid] = []

        if t.retval.isnumeric():
            t.retval = int(t.retval)
        active_pids[t.pid].append((idx, t))

        if t.syscall_name == 'fork' or t.syscall_name == 'clone':
            # RV is child
            if t.retval >= 0:
                parent_to_children[t.pid].append(t.retval)

        for arg in t.syscall_args:
            s_str = stracify_str(input_data)
            if s_str in arg:
                #print(f"FOUND INPUT {input_data[:10]} IN {s(t)}")
                input_recvs.append(idx) # It showed up in an arg. Assume it's an input consumer
                break
        idx += 1

    for pid, data in active_pids.items():
        print('------', pid)
        if pid in parent_to_children and len(parent_to_children[pid]):
            print("\t**has children: ", parent_to_children[pid])
        for (t_idx, t) in data:
            print(f'{t_idx: >3}, {s(t)}')
            if t_idx in input_recvs:
                print("\t**Input rev")
        print()


def main(bin_trace_map):
    # Trace map is {bin_a: [(input1, [trace_of_input_1], ...)], bin_b: ...}

    # BUT: we might have the same inputs in our list for a binary IFF that binary
    # bound in multiple ways (i.e.: tcp + udp, two ports)
    for binary, data in bin_trace_map.items():
        if sum([len(trace_list) for _, trace_list in data]) == 0:
            print(f"----- SKipping {binary} since it generated no traces")
            continue
        print()
        print("-"*30 + binary + "-"*30)
        for (input_data, trace_list)  in data:
            analyze(input_data, trace_list)

if __name__ == '__main__':
    with open("traces.pickle", "rb") as f:
        main(pickle.load(f))
