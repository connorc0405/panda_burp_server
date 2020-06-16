#!/usr/bin/env python3
# Take a recording, then replay and analyze


from os import path
from panda import Panda, blocking
import subprocess


# Need to include at top-level for ppp decorator
panda = Panda(arch='x86_64', mem='1G', qcow='/panda_resources/bionic-work.qcow2', expect_prompt=rb'root@ubuntu:.*# ', extra_args='-display none -net user,hostfwd=tcp::8080-:80 -net nic')

recording_name = 'record_query_secret_str'


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


def main():

    if not (path.isfile(recording_name+"-rr-nondet.log") and path.isfile(recording_name+"-rr-snp")):
        print("======== TAKE RECORDING ========")
        panda.queue_async(record_curl)
        panda.run()
        print("======== END RECORDING ========")
    
if __name__ == '__main__':
    main()

