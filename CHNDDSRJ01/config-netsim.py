#!/usr/bin/env python3
"""
Bootstraps a netsim with given config.  Unsupported lines by the NED will be written to a separate file.
"""
# noinspection SpellCheckingInspection
__author__ = "Ash Sadasivan"
__copyright__ = "Copyright 2023, CISCO SYSTEMS, INC. ALL RIGHTS RESERVED."

import argparse
import paramiko
import time
import subprocess

parser = argparse.ArgumentParser(description='Bootstraps a netsim with given config.'
                                             'Unsupported lines by the NED will be written to a separate file.')
parser.add_argument("-t", "--device_type", choices=['Juniper', 'Arista'], default='Juniper')
parser.add_argument("-f", "--config_file_name", required=True, help="Full config file for device.")
parser.add_argument("-d", "--device_name", help="The netsim to load config to.")
parser.add_argument("-c", "--commit", action='store_true', help="Commit the config to the netsim.")
parser.add_argument("-p", "--print", action='store_true', help="Print communication with netsim.")
args = parser.parse_args()


def ssh_to_device():
    # noinspection PyGlobalUndefined
    global ssh_shell
    device = args.device_name
    if not device:
        device = 'junos-1'
    result = subprocess.run(['ncs-netsim', 'get-port', device, 'cli'], stdout=subprocess.PIPE)
    port = int(result.stdout.decode('utf-8'))
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect('127.0.0.1', port=port, username='admin', password='admin', look_for_keys=False)
    ssh_shell = ssh.invoke_shell()


def issue_command(command):
    ssh_shell.send('%s\n' % command)
    time.sleep(0.2)
    cmd_output = ssh_shell.recv(1000).decode("utf-8")
    if args.print:
        print(cmd_output)
    return cmd_output


def transform_config_line():
    global new_line
    if args.device_type == 'Juniper':
        if new_line.startswith('set configuration interfaces '):
            if not new_line.startswith('set configuration interfaces apply') and \
                    not new_line.startswith('set configuration interfaces interface-') and \
                    not new_line.startswith('set configuration interfaces pic-set') and \
                    not new_line.startswith('set configuration interfaces traceoptions'):
                new_line = new_line.replace('set configuration interfaces ',
                                            'set configuration interfaces interface ', 1)


cfg_file = args.config_file_name
if cfg_file.find('.') != -1:
    cfg_file_name = cfg_file.split('.')
    cfg_file_prefix = cfg_file_name[0]
    cfg_file_suffix = cfg_file_name[1]
else:
    cfg_file_prefix = cfg_file
    cfg_file_suffix = 'txt'
sup_cfg_file_name = cfg_file_prefix + '-sup' + '.' + cfg_file_suffix
unsup_cfg_file_name = cfg_file_prefix + '-unsup' + '.' + cfg_file_suffix
cfg_set_file_name = cfg_file_prefix + '-set-cfg.txt'

with open(args.config_file_name, 'r', encoding='utf-8-sig') as cfg_file, \
        open(sup_cfg_file_name, 'w', encoding='utf-8-sig') as sup_cfg_file, \
        open(unsup_cfg_file_name, 'w', encoding='utf-8-sig') as unsup_cfg_file, \
        open(cfg_set_file_name, 'w', encoding='utf-8-sig') as cfg_set_file:
    ssh_to_device()
    issue_command('configure')
    for line in cfg_file:
        new_line = line.replace('set ', 'set configuration ', 1)
        transform_config_line()

        output = issue_command(new_line)
        if output.find('syntax error:') != -1:
            unsup_cfg_file.write(line)
        else:
            sup_cfg_file.write(line)
            cfg_set_file.write(new_line)

    if args.commit:
        issue_command('commit')
    else:
        issue_command('revert')
        issue_command('yes')

    issue_command('exit')
    # TODO: Fix me
    issue_command('show configuration | display xml | save overwrite /tmp/' + cfg_file_prefix + '.xml')
    issue_command('exit')
