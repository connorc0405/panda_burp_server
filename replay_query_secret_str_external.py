#!/usr/bin/env python3
# Take a recording, then replay and analyze


from os import path
from panda import Panda, ffi


# Need to include at top-level for ppp decorator
panda = Panda(arch='x86_64', mem='1G', qcow='/panda_resources/bionic-work.qcow2', expect_prompt=rb'root@ubuntu:.*# ', extra_args='-display none -net user,hostfwd=tcp::8080-:80 -net nic')

recording_name = 'record_query_secret_str'

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

    if name == b'querystr.cgi':
        print(f'BRANCH at addr {addr} was tainted in proc {name}')
    # Get disassembled code, figure out what is being compared


def main():

    if not (path.isfile(recording_name+"-rr-nondet.log") and path.isfile(recording_name+"-rr-snp")):
        print('Record and/or replay file does not exist')

    print("======== RUN REPLAY ========")
    panda.load_plugin('taint2')
    panda.load_plugin('tainted_branch')
    panda.load_plugin('tainted_net', {'label_incoming_network': True, 'ip_src':'10.0.2.2', 'packets':'7'})
    panda.set_os_name("linux-64-ubuntu:4.15.0-72-generic")
    panda.load_plugin("osi", {"disable-autoload": True})
    panda.load_plugin("osi_linux", {"kconf_file": "/panda_resources/kernelinfo-noaslr-nokaslr.conf", "kconf_group": "ubuntu:4.15.0-72-generic-noaslr-nokaslr:64"})
    panda.run_replay(recording_name) # Load and run the replay
    print("======== FINISH REPLAY ========")



    panda.end_analysis()
   
if __name__ == '__main__':
    main()


# TODO Register python callback with tainted_branch
# TODO then look for CGI process running
# TODO then disassemble code.

