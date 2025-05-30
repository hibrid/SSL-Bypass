#!/usr/bin/env python3

import platform, os, sys, colorama, ssl, glob, argparse, textwrap, time, shutil, subprocess, zipfile, difflib
from pathlib import Path
from signal import signal, SIGINT
from urllib import request
from lxml import etree
import tempfile

# enabling color for Windows CMD and PowerShell
colorama.init()
ssl._create_default_https_context = ssl._create_unverified_context

script_version = '1.1'
prefix = Path(sys.argv[0]).resolve().name
output_suffix = '-patched'
output_ext = '.apk'
decomp_dir_suffix = '-decompiled'
garbage = {'files': [], 'dirs': []}

def run(cmd):
    subprocess.run(cmd, check=True)

def diff_files(original, modified):
    with open(original) as f1, open(modified) as f2:
        orig_lines = f1.readlines()
        mod_lines = f2.readlines()
    return ''.join(difflib.unified_diff(orig_lines, mod_lines, fromfile='original', tofile='modified'))

def check_tools():
    tools_dir.mkdir(parents=True, exist_ok=True)
    for tool in tools_data:
        tool_file = tools_dir / f"{tool['file_name']}{tool['version']}.jar"
        if not tool_file.exists():
            request.urlretrieve(f"{tool['url']}{tool['version']}/{tool['file_name']}{tool['version']}.jar", tool_file)

class colors:
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

tools_data = [
    {'file_name': 'bundletool-all-', 'version': '1.15.6', 'url': 'https://github.com/google/bundletool/releases/download/', 'name': 'bundletool'},
    {'file_name': 'apktool_', 'version': '2.9.1', 'url': 'https://github.com/iBotPeaches/Apktool/releases/download/v', 'name': 'apktool'},
    {'file_name': 'uber-apk-signer-', 'version': '1.2.1', 'url': 'https://github.com/patrickfav/uber-apk-signer/releases/download/v', 'name': 'uber-apk-signer'}
]

home_path = Path.home()
tools_dir = home_path / '.config' / 'apk-rebuild'

apktool_path = tools_dir / f"apktool_{tools_data[1]['version']}.jar"
uber_apk_signer_path = tools_dir / f"uber-apk-signer-{tools_data[2]['version']}.jar"

parser = argparse.ArgumentParser()
parser.add_argument('apk', help='APK file')
parser.add_argument('--interactive', action='store_true', help='Interactive XML modification')
parser.add_argument('--preserve', action='store_true', help='Preserve unpacked content')
parser.add_argument('--ks', help='Keystore file')
parser.add_argument('--ks-pass', help='Keystore pass')
parser.add_argument('--ks-alias', help='Keystore alias')
parser.add_argument('--ks-alias-pass', help='Alias pass')
args = parser.parse_args()

check_tools()
unpack_dir = Path(str(args.apk) + decomp_dir_suffix)

run(['java', '-jar', str(apktool_path), 'decode', args.apk, '-o', unpack_dir, '-f'])

ns_config = unpack_dir / 'res/xml/network_security_config.xml'

if args.interactive:
    mode = input('Manual or auto fix? [manual/auto]: ').strip().lower()
    if mode == 'manual':
        input('Make your manual edits, then press ENTER to continue...')
    else:
        orig_backup = ns_config.with_suffix('.bak')
        shutil.copy2(ns_config, orig_backup)

        tree = etree.parse(str(ns_config))
        modified = False

        base_config = tree.find("base-config") or etree.SubElement(tree.getroot(), 'base-config', cleartextTrafficPermitted="false")
        trust_anchors = base_config.find("trust-anchors") or etree.SubElement(base_config, 'trust-anchors')
        if not trust_anchors.xpath("certificates[@src='user']"):
            etree.SubElement(trust_anchors, 'certificates', src="user")
            modified = True

        if modified:
            tree.write(str(ns_config), pretty_print=True, encoding='utf-8', xml_declaration=True)
            diff = diff_files(orig_backup, ns_config)
            print('Changes proposed:')
            print(diff)
            if input('Apply changes? [y/n]: ').lower() != 'y':
                shutil.copy(orig_backup, ns_config)

aligned_apk = Path(args.apk).with_suffix('.aligned.apk')
rebuilt_apk = aligned_apk.with_suffix('.patched.apk')

run(['java', '-jar', str(apktool_path), 'build', unpack_dir, '-o', rebuilt_apk])
run(['zipalign', '-f', '-p', '4', rebuilt_apk, aligned_apk])
sign_cmd = ['java', '-jar', str(uber_apk_signer_path), '-a', aligned_apk, '--allowResign', '--overwrite']
if args.ks:
    sign_cmd += ['--ks', args.ks, '--ksPass', args.ks_pass, '--ksAlias', args.ks_alias, '--ksKeyPass', args.ks_alias_pass]
run(sign_cmd)

print(f'{colors.OKGREEN}APK rebuilt, aligned, signed: {aligned_apk}{colors.ENDC}')

if args.interactive and not args.preserve:
    if input('Delete unbundled folder? [y/n]: ').lower() == 'y':
        shutil.rmtree(unpack_dir)
