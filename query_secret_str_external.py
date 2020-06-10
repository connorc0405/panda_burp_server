#!/usr/bin/env python3
# Take a recording, then replay and analyze


from os import remove, path
from panda import Panda, blocking
import subprocess


@blocking
def record_curl(): # Run a non-deterministic command at the root snapshot, then end .run()
    panda.revert_sync('root')
    print('Fixing guest network')
    panda.run_serial_cmd('/root/fix_network.sh')
    panda.run_monitor_cmd("begin_record {}".format(recording_name))
    print('Running CURL from Docker')
    subprocess.run(['curl', 'localhost:8080/cgi-bin/querystr.cgi?SECRE'])
    panda.run_monitor_cmd("end_record")
    panda.stop_run()


def main():
    panda = Panda(arch='x86_64', mem='1G', qcow='/panda_resources/bionic-work.qcow2', expect_prompt=rb'root@ubuntu:.*# ', extra_args='-display none -net user,hostfwd=tcp::8080-:80 -net nic')        

    # Make sure we're always saving a new recording
    recording_name = "record_query_secret_str"
    for f in [recording_name+"-rr-nondet.log", recording_name+"-rr-snp"]:
        if path.isfile(f): remove(f)
    
    print("======== TAKE RECORDING ========")
    panda.queue_async(record_curl) # Take a recording
    panda.run()
    print("======== END RECORDING ========")

    print("======== RUN REPLAY ========")
    panda.run_replay(recording_name) # Load and run the replay
    print("======== FINISH REPLAY ========")

   
if __name__ == '__main__':
    main()


# TODO Register python callback with tainted_branch
# TODO then look for CGI process running
# TODO then disassemble code.

