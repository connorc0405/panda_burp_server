#!/usr/bin/env python3
# Replay and analyze a recording


from os import path
import sys


from panda import Panda, ffi
from panda.x86.helper import *


# Need to include at top-level for ppp decorator
panda = Panda(arch='x86_64', mem='1G', qcow='/panda_resources/bionic-work.qcow2', expect_prompt=rb'root@ubuntu:.*# ', extra_args='-display none -net user,hostfwd=tcp::8080-:80 -net nic')


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

ffi.cdef("""
        struct sockaddr {
            unsigned short sa_family;	/* address family, AF_xxx	*/
            char sa_data[14];	/* 14 bytes of protocol address	*/
        };

        struct in_addr {
	        uint32_t s_addr;
        };

        struct sockaddr_in {
            unsigned short sin_family; /* address family: AF_INET */
            uint16_t sin_port;   /* port in network byte order */
            uint32_t sin_addr;   /* internet address */
            unsigned char __pad[8];  // 16 - sizeof(short int) - sizeof(unsigned short int) - sizeof(struct in_addr)
        };
""")

# TODO without this, PANDA[osi_linux]:E:osi_linux.cpp(init_per_cpu_offsets)> Unable to update value of ki.task.per_cpu_offset_0_addr.
# python3: /panda/panda/plugins/osi_linux/osi_linux.cpp:609: void init_per_cpu_offsets(CPUState*): Assertion `false' failed.
@panda.ppp("taint2", "on_branch2")
def tainted_branch(addr, size):
    cpu = panda.get_cpu()
    pc = panda.current_pc(cpu)
    proc = panda.plugins['osi'].get_current_process(cpu)
    name = ffi.string(proc.name)

    # if name == b'querystr.cgi':
    print(f'BRANCH at addr {addr} was tainted in proc {name}')
    # Get disassembled code, figure out what is being compared


net_fds = set()

panda.set_os_name("linux-64-ubuntu:4.15.0-72-generic")
# TODO: expose a filter (source port, ip, dest port)??
@panda.ppp("syscalls2", "on_sys_accept4_return")
def on_sys_accept4_return(cpu, pc, sockfd, addr, addr_len, flags):
    newfd = cpu.env_ptr.regs[R_EAX]
    proc = panda.plugins['osi'].get_current_process(cpu)
    proc_name = ffi.string(proc.name)
    
    net_fds.add((proc_name, newfd))  # Each process has its own fd space.
    
    # protocol_bytes = panda.virtual_memory_read(cpu, addr, 2)
    # if int.from_bytes(protocol_bytes, 'little') in [2, 10]:  # Looking for AF_INET(6)
        # sockaddr_bytes = panda.virtual_memory_read(cpu, addr, ffi.sizeof('struct sockaddr_in'))
        # print(f"Sin_port: {int.from_bytes(sockaddr_bytes[2:4], 'big')}")
        # print(f"Sin_addr: {[int(sockaddr_bytes[x]) for x in range(4,8)]}")
        # print(f"Size of sockaddr_in: {ffi.sizeof('struct sockaddr_in')}")
        # print(f"How many bytes we have: {len(sockaddr_bytes)}")

        # s_struct = ffi.new("struct sockaddr_in *")
        # s_buffer = ffi.buffer(s_struct)
        # s_buffer[:] = sockaddr_bytes
        # print(s_struct.sin_family)
        # print(s_struct.sin_port)
        # print(s_struct.sin_addr)
        # sockaddr = ffi.cast("struct sockaddr_in", sockaddr_bytes)


taint_selection = None

# TODO: we should hook calls to vfs_read instead of syscalls
@panda.ppp("syscalls2", "on_sys_read_return")
def on_sys_read_return(cpu, pc, fd, buf, count):
    # XXX: taint labels are applied in main_loop_wait so this might be completley
    # broken depending on when that runs (hopefully at the return?)
    # This needs testing. See taint_mixins.py:37
    taint_idx = 0

    proc = panda.plugins['osi'].get_current_process(cpu)
    proc_name = ffi.string(proc.name)

    if (proc_name, fd) in net_fds:
        bytes_written = cpu.env_ptr.regs[R_EAX]
        data = panda.virtual_memory_read(cpu, buf, bytes_written)

        if not b'HTTP/' in data in data:
            print(f"Not tainting buffer: {repr(data)}")
            return # Don't taint non HTTP.  Issues if requests get buffered TODO

        # Label tainted (physical) addresses
        taint_groups = taint_selection.split(',')  # What if just 1 byte/group?
        for group in taint_groups:  # While we are parsing the taint string
            if len(group) == 1:  # One byte
                taint_offset = int(group)
                taint_paddr = panda.virt_to_phys(cpu, buf + taint_offset) # Physical address
                panda.taint_label_ram(taint_paddr, taint_idx)
                print(f"tainted byte {data[taint_offset]} with index {taint_idx}")
            else:  # Range of bytes (i.e. 0:5)
                assert type(group) == str
                assert group[1] == ':'
                for taint_offset in range(int(group[0]), int(group[2])+1):
                    taint_paddr = panda.virt_to_phys(cpu, buf + taint_offset) # Physical address
                    panda.taint_label_ram(taint_paddr, taint_idx)
                    print(f"tainted byte {data[taint_offset]} with index {taint_idx}")
            taint_idx += 1


@panda.ppp("syscalls2", "on_sys_close_enter")
def on_sys_close_enter(cpu, pc, fd):
    proc = panda.plugins['osi'].get_current_process(cpu)
    proc_name = ffi.string(proc.name)
    if (proc_name, fd) in net_fds:
        net_fds.remove((proc_name, fd))


def main():

    recording_name = sys.argv[1]
    global taint_selection
    taint_selection = sys.argv[2]

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
