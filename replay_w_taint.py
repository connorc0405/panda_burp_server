#!/usr/bin/env python3
# Replay and analyze a recording


from os import path
from panda import Panda, ffi
from panda.x86.helper import *
import ctypes


# Need to include at top-level for ppp decorator
panda = Panda(arch='x86_64', mem='1G', qcow='/panda_resources/bionic-work.qcow2', expect_prompt=rb'root@ubuntu:.*# ', extra_args='-display none -net user,hostfwd=tcp::8080-:80 -net nic')

recording_name = 'testing_testing2'


# Hacky code to get on_branch2 PPP callback working in pypanda
# CFFI Can't typedef structures with unions, like addrs
# So here we replace `val` with a uint64_t 'addr_val'
ffi.cdef("""
        typedef struct {
            AddrType typ;
            uint64_t addr_val;
            uint16_t off;
            AddrFlag flag;
        } FakeAddr;
""")
ffi.cdef('typedef void (*on_branch2_t) (FakeAddr, uint64_t);', override=True) # XXX WIP
ffi.cdef('void ppp_add_cb_on_branch2(on_branch2_t);') # Why don't we autogen this? Are we not translating the macros into fn defs?
# End hacky-CFFI codev


@panda.ppp("taint2", "on_branch2")
def tainted_branch(addr, size):
    cpu = panda.get_cpu()
    pc = panda.current_pc(cpu)
    proc = panda.plugins['osi'].get_current_process(cpu)
    name = ffi.string(proc.name)

    # if name == b'querystr.cgi':
    print(f'BRANCH at addr {addr} was tainted in proc {name}')
    # Get disassembled code, figure out what is being compared


taint_idx = 0 # Each request increments
net_fds = set()

panda.set_os_name("linux-64-ubuntu:4.15.0-72-generic")

# TODO: expose a port-specific filter
# TODO accept vs accept4???
@panda.ppp("syscalls2", "on_sys_accept4_return")
def on_sys_accept_return(cpu, pc, sockfd, addr, addrLen, junk):
    newfd = cpu.env_ptr.regs[R_EAX]
    print(f"Accept on {sockfd}, new FD is {newfd}")
    net_fds.add(newfd)

# TODO: we should hook calls to vfs_read instead of syscalls
@panda.ppp("syscalls2", "on_sys_read_return")
def on_sys_read_return(cpu, pc, fd, buf, count):
    # XXX: taint labels are applied in main_loop_wait so this might be completley
    # broken depending on when that runs (hopefully at the return?)
    # This needs testing. See taint_mixins.py:37
    global taint_idx

    if fd in net_fds:
        bytes_written = cpu.env_ptr.regs[R_EAX]
        data = panda.virtual_memory_read(cpu, buf, bytes_written)

        if not b'GET' in data and not b'POST' in data:
            print(f"Not tainting buffer: {repr(data)}")
            return # Don't taint non HTTP. Might have issues if requested get buffered TODO

        # Label each tainted (physical) address
        for taint_vaddr in range(buf, buf+bytes_written):
            taint_paddr = panda.virt_to_phys(cpu, taint_vaddr) # Physical address
            panda.taint_label_ram(taint_paddr, taint_idx)

        # Increment label for next request
        taint_idx += 1
    else:
        return # We shouldn't need this because our FD will be created (accept() syscall will be called) during the replay
        # SUPER HACKY - but syscalls aren't finidng the accept
        bytes_written = cpu.env_ptr.regs[R_EAX]
        data = panda.virtual_memory_read(cpu, buf, bytes_written)

        if b'GET' in data or b'POST' in data:
            print(f"Tainting {bytes_written}-byte buffer from fd {fd} with label {taint_idx}",
                    repr(data)[:30], "...")

            # Label each tainted (physical) address
            for taint_vaddr in range(buf, buf+bytes_written):
                taint_paddr = panda.virt_to_phys(cpu, taint_vaddr) # Physical address
                panda.taint_label_ram(taint_paddr, taint_idx)

            # Increment label for next request
            taint_idx += 1

@panda.ppp("syscalls2", "on_sys_close_enter")
def on_sys_close_enter(cpu, pc, fd):
    if fd in net_fds:
        net_fds.remove(fd)

def main():

    if not (path.isfile(recording_name+"-rr-nondet.log") and path.isfile(recording_name+"-rr-snp")):
        print('Record and/or replay file does not exist')

    print("======== RUN REPLAY ========")
    panda.load_plugin('taint2')
    panda.load_plugin('tainted_branch')
    panda.load_plugin("osi", {"disable-autoload": True})
    panda.load_plugin("osi_linux", {"kconf_file": "/panda_resources/kernelinfo-noaslr-nokaslr.conf", "kconf_group": "ubuntu:4.15.0-72-generic-noaslr-nokaslr:64"})
    panda.load_plugin('syscalls2', {'load-info': True})

    panda.run_replay(recording_name) # Load and run the replay

    print("======== FINISH REPLAY ========")
    
    panda.end_analysis()


if __name__ == '__main__':
    main()


# TODO capture HTTP from socket read and apply taint that was chosen in BURP.
