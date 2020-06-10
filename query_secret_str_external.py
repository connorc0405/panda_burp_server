#!/usr/bin/env python3
# Take a recording, then replay and analyze


from os import remove, path
from panda import Panda, blocking, ffi
import subprocess


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


@blocking
def record_curl(): # Run a non-deterministic command at the root snapshot, then end .run()
    panda.revert_sync('root')
    print('Fixing guest network...')
    panda.run_serial_cmd('/root/fix_network.sh')
    print('Beginning recording...')
    panda.run_monitor_cmd("begin_record {}".format(recording_name))
    print('Running CURL from Docker')
    subprocess.run(['curl', 'localhost:8080/cgi-bin/querystr.cgi?SECRE'])
    panda.run_monitor_cmd("end_record")
    panda.stop_run()


#@panda.ppp("taint2", "on_branch2")
#def tainted_branch(addr, size):
#    #proc =
#    print(f'BRANCH at addr {addr} was tainted in proc {proc}')


def main():

    # Make sure we're always saving a new recording
    for f in [recording_name+"-rr-nondet.log", recording_name+"-rr-snp"]:
        if path.isfile(f): remove(f)
    
    print("======== TAKE RECORDING ========")
    panda.queue_async(record_curl) # Take a recording
    panda.run()
    print("======== END RECORDING ========")

    print("======== RUN REPLAY ========")
    #panda.load_plugin('taint2')
    #panda.load_plugin('tainted_branch')
    #panda.load_plugin('tainted_net', {'label_incoming_network': True})
    panda.run_replay(recording_name) # Load and run the replay
    print("======== FINISH REPLAY ========")

    #panda.end_analysis()
   
if __name__ == '__main__':
    main()


# TODO Register python callback with tainted_branch
# TODO then look for CGI process running
# TODO then disassemble code.

