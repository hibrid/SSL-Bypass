#!/usr/bin/env python3

import os, sys, ssl, argparse, subprocess, shutil, zipfile, difflib, json
from pathlib import Path
from lxml import etree
import hashlib
from urllib import request
from typing import Dict, List, Optional, Union

ssl._create_default_https_context = ssl._create_unverified_context

script_version = '2.0'
decomp_dir_suffix = '-decompiled'

# Tool management
tools_data = [
    {'file_name': 'apktool_', 'version': '2.9.1', 'url': 'https://github.com/iBotPeaches/Apktool/releases/download/v', 'name': 'apktool'},
    {'file_name': 'uber-apk-signer-', 'version': '1.2.1', 'url': 'https://github.com/patrickfav/uber-apk-signer/releases/download/v', 'name': 'uber-apk-signer'}
]

home_path = Path.home()
tools_dir = home_path / '.config' / 'apk-rebuild'
tools_dir.mkdir(parents=True, exist_ok=True)

# Default configuration
DEFAULT_CONFIG = {
    "allow_cleartext": True,
    "trust_system": True,
    "trust_user": True,
    "remove_pins": True,
    "cleanup": True,
    "continue_on_missing": True,
    "search_path": ".",
    "non_interactive": False,
    "ks": None,
    "ks_pass": None,
    "ks_alias": None,
    "ks_alias_pass": None,
    "output_dir": "output"  # Default output directory
}

def load_config(config_path: str) -> Dict:
    """Load configuration from JSON file."""
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
            # Validate required fields
            if 'files' not in config:
                raise ValueError("Config must contain 'files' section")
            
            # Apply global options to all files if not specified
            global_options = {k: v for k, v in config.items() if k != 'files'}
            for file_config in config['files']:
                if 'options' not in file_config:
                    file_config['options'] = {}
                # Merge global options with file-specific options
                for key, value in global_options.items():
                    if key not in file_config['options']:
                        file_config['options'][key] = value
                # Ensure all required options are present
                for key, value in DEFAULT_CONFIG.items():
                    if key not in file_config['options']:
                        file_config['options'][key] = value
            
            return config
    except Exception as e:
        print(f"Error loading config file: {e}")
        sys.exit(1)

def find_apks(path: Union[str, Path]) -> List[Path]:
    """Find all APK files in the given path."""
    path = Path(path)
    if path.is_file():
        return [path] if path.suffix.lower() == '.apk' else []
    return list(path.glob('**/*.apk'))

def select_apks(apks: List[Path]) -> List[Path]:
    """Prompt user to select APKs to process."""
    if not apks:
        print("No APK files found.")
        sys.exit(1)

    print("\nFound APK files:")
    for i, apk in enumerate(apks, 1):
        print(f"{i}. {apk.name}")
    print("A. Process all APKs")
    print("Q. Quit")

    while True:
        choice = input("\nSelect APKs to process (comma-separated numbers, 'A' for all, 'Q' to quit): ").strip().upper()
        if choice == 'Q':
            sys.exit(0)
        if choice == 'A':
            return apks

        try:
            indices = [int(x.strip()) for x in choice.split(',')]
            selected = [apks[i-1] for i in indices if 0 < i <= len(apks)]
            if selected:
                return selected
        except ValueError:
            pass
        print("Invalid selection. Please try again.")

def get_default_options() -> Dict:
    """Get default options for APK processing."""
    return {
        "allow_cleartext": True,
        "trust_system": True,
        "trust_user": True,
        "remove_pins": True,
        "cleanup": True
    }

def prompt_for_options() -> Dict:
    """Prompt user for processing options."""
    print("\nDefault options:")
    print("1. Allow cleartext traffic: true")
    print("2. Trust system certificates: true")
    print("3. Trust user certificates: true")
    print("4. Remove certificate pins: true")
    print("5. Clean up after processing: true")
    
    if input("\nUse default options? [y/n]: ").lower() == 'y':
        return get_default_options()

    options = {}
    options["allow_cleartext"] = input("Allow cleartext traffic? [true/false]: ").lower() == 'true'
    options["trust_system"] = input("Trust system certificates? [true/false]: ").lower() == 'true'
    options["trust_user"] = input("Trust user certificates? [true/false]: ").lower() == 'true'
    options["remove_pins"] = input("Remove certificate pins? [true/false]: ").lower() == 'true'
    options["cleanup"] = input("Clean up after processing? [true/false]: ").lower() == 'true'
    return options

def check_tools():
    for tool in tools_data:
        tool_file = tools_dir / f"{tool['file_name']}{tool['version']}.jar"
        if not tool_file.exists():
            print(f"Downloading {tool['name']}...")
            request.urlretrieve(f"{tool['url']}{tool['version']}/{tool['file_name']}{tool['version']}.jar", tool_file)
    return tools_dir / f"apktool_{tools_data[0]['version']}.jar", tools_dir / f"uber-apk-signer-{tools_data[1]['version']}.jar"

def run(cmd):
    subprocess.run(cmd, check=True)

def sha256_digest(cert_path):
    try:
        with open(cert_path, 'rb') as f:
            data = f.read()
        cert = ssl.DER_cert_to_PEM_cert(data) if data.startswith(b'\x30') else data.decode()
        lines = [line.strip() for line in cert.splitlines() if line and 'BEGIN' not in line and 'END' not in line]
        der = ssl.PEM_cert_to_DER_cert(f"-----BEGIN CERTIFICATE-----\n{''.join(lines)}\n-----END CERTIFICATE-----\n")
        return hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert)).digest().encode('base64').strip()
    except Exception as e:
        print(f"Certificate validation error: {e}")
        return None

def diff(orig, new):
    diff = difflib.unified_diff(orig.splitlines(), new.splitlines(), 'Original', 'Modified', lineterm='')
    print('\n'.join(diff))

def modify_xml(path: Path, options: Dict) -> str:
    """Modify network security config XML based on options."""
    tree = etree.parse(path)
    root = tree.getroot()

    base = root.find('base-config')
    if base is None:
        base = etree.SubElement(root, 'base-config')

    # Handle cleartext traffic
    base.set('cleartextTrafficPermitted', str(options.get('allow_cleartext', True)).lower())

    # Handle trust anchors
    ta = base.find('trust-anchors') or etree.SubElement(base, 'trust-anchors')
    for src in ['system', 'user']:
        if options.get(f'trust_{src}', True):
            if ta.find(f".//certificates[@src='{src}']") is None:
                etree.SubElement(ta, 'certificates', src=src)

    # Handle certificate pins
    domains = root.findall('domain-config')
    if domains:
        if not options.get('remove_pins', True):
            if not options.get('non_interactive', False):
                print("Pinned domains detected:")
                for i, dc in enumerate(domains, 1):
                    domain = dc.find('domain').text
                    print(f"{i}. {domain}")

                choice = input("Apply same decision to all domains? [yes/no]: ").lower() == 'yes'
                decision = None
                for dc in domains:
                    domain = dc.find('domain').text
                    if not choice or decision is None:
                        print(f"Domain '{domain}':")
                        decision = input("[1] Remove pins\n[2] Add custom pin\n[3] Skip\nSelect: ")
                    if decision == '1':
                        root.remove(dc)
                    elif decision == '2':
                        while True:
                            cert_path = input("Path to cert file: ")
                            digest = sha256_digest(cert_path)
                            if digest:
                                pinset = dc.find('pin-set') or etree.SubElement(dc, 'pin-set')
                                pinset.clear()
                                etree.SubElement(pinset, 'pin', digest='SHA-256').text = digest
                                include_sub = input("Include subdomains? [true/false]: ").lower()
                                dc.find('domain').set('includeSubdomains', include_sub)
                                break
                            else:
                                if not options.get('non_interactive', False):
                                    retry = input("Certificate validation failed. Try again with new values? [y/n]: ").lower()
                                    if retry != 'y':
                                        print("Skipping pin for this domain...")
                                        break
                                else:
                                    print("Certificate validation failed. Skipping pin for this domain...")
                                    break
                    else:
                        continue
            else:
                # In non-interactive mode, keep pins if remove_pins is false
                pass
        else:
            # Remove all pins if remove_pins is true
            for dc in domains:
                root.remove(dc)

    # Handle user certificate installation
    if not options.get('non_interactive', False):
        if input("Do you want to rename and install a certificate? [y/n]: ").lower() == 'y':
            cert_path = input("Path to certificate file: ")
            if os.path.exists(cert_path):
                try:
                    hash_output = subprocess.check_output(['openssl', 'x509', '-subject_hash_old', '-in', cert_path], text=True)
                    cert_hash = hash_output.split('\n')[0].strip()
                    new_cert_path = f"{cert_hash}.0"
                    shutil.copy2(cert_path, new_cert_path)
                    print(f"\nCertificate renamed to: {new_cert_path}")
                    
                    # Print installation instructions
                    print("\nCertificate Installation Instructions:")
                    print("1. Enable root access on device:")
                    print("   ./adb root")
                    print(f"2. Push certificate to device:")
                    print(f"   ./adb push {new_cert_path} /system/etc/security/cacerts")
                    print("\nApp Installation Instructions:")
                    print("1. Uninstall existing app:")
                    print("   ./adb uninstall <package_name>")
                    print("2. Install new version:")
                    print("   ./adb install-multiple -r --no-incremental <aligned_apk_files>")
                except subprocess.CalledProcessError as e:
                    print(f"Warning: Error getting certificate hash: {e}")
                    print("Continuing without certificate installation...")
            else:
                print(f"Warning: Certificate file not found: {cert_path}")
                print("Continuing without certificate installation...")

    return etree.tostring(root, pretty_print=True, encoding='utf-8', xml_declaration=True).decode()

def create_network_security_config():
    """Create a default network security config XML."""
    root = etree.Element('network-security-config')
    debug_overrides = etree.SubElement(root, 'debug-overrides')
    trust_anchors = etree.SubElement(debug_overrides, 'trust-anchors')
    etree.SubElement(trust_anchors, 'certificates', src='user')
    return etree.tostring(root, pretty_print=True, encoding='utf-8', xml_declaration=True).decode()

def ensure_manifest_reference(manifest_path):
    """Ensure the manifest references the network security config."""
    tree = etree.parse(manifest_path)
    root = tree.getroot()
    app = root.find('.//application')
    
    if app is not None:
        # Check if networkSecurityConfig attribute exists
        if app.get('{http://schemas.android.com/apk/res/android}networkSecurityConfig') is None:
            app.set('{http://schemas.android.com/apk/res/android}networkSecurityConfig', '@xml/network_security_config')
            tree.write(manifest_path, pretty_print=True, encoding='utf-8', xml_declaration=True)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('path', nargs='?', help='APK file, directory containing APKs, or config file')
    parser.add_argument('--config', help='Path to config file')
    parser.add_argument('--non-interactive', action='store_true', help='Run in non-interactive mode using defaults')
    parser.add_argument('--ks', help='Keystore file')
    parser.add_argument('--ks-pass', help='Keystore pass')
    parser.add_argument('--ks-alias', help='Keystore alias')
    parser.add_argument('--ks-alias-pass', help='Keystore alias pass')
    parser.add_argument('--output-dir', help='Output directory for processed files (default: ./output)')
    args = parser.parse_args()

    # Get tool paths
    apktool_path, uber_signer_path = check_tools()

    # Set up output directory
    output_dir = Path(args.output_dir) if args.output_dir else Path(DEFAULT_CONFIG['output_dir'])
    output_dir.mkdir(parents=True, exist_ok=True)

    # Handle config file
    if args.config:
        config = load_config(args.config)
        # Process files according to config
        for file_config in config['files']:
            apk_path = Path(file_config['path'])
            if not apk_path.exists():
                if file_config['options'].get('continue_on_missing', True):
                    print(f"Warning: File {apk_path} not found, skipping...")
                    continue
                else:
                    print(f"Error: File {apk_path} not found")
                    sys.exit(1)
                    
            # Create args namespace with config options
            config_args = argparse.Namespace(
                non_interactive=file_config['options'].get('non_interactive', False),
                ks=file_config['options'].get('ks'),
                ks_pass=file_config['options'].get('ks_pass'),
                ks_alias=file_config['options'].get('ks_alias'),
                ks_alias_pass=file_config['options'].get('ks_alias_pass'),
                output_dir=file_config['options'].get('output_dir', output_dir)
            )
            
            process_apk(apk_path, file_config['options'], apktool_path, uber_signer_path, config_args)
        return

    # Handle path argument
    if not args.path:
        # Find APKs in current directory
        apks = find_apks('.')
    else:
        path = Path(args.path)
        if path.is_file() and path.suffix.lower() == '.apk':
            apks = [path]
        elif path.is_dir():
            apks = find_apks(path)
        else:
            print(f"Invalid path: {args.path}")
            sys.exit(1)

    # Select APKs to process
    if not args.non_interactive:
        apks = select_apks(apks)
    else:
        # In non-interactive mode, process all found APKs
        pass

    # Sort APKs to process base.apk first if it exists
    base_apk = next((apk for apk in apks if apk.name.lower() == 'base.apk'), None)
    if base_apk:
        apks.remove(base_apk)
        apks.insert(0, base_apk)

    # Get processing options
    if args.non_interactive:
        options = get_default_options()
    else:
        options = prompt_for_options()
        if len(apks) > 1:
            if input("\nApply these options to all APKs? [y/n]: ").lower() != 'y':
                options = None  # Will prompt for each APK

    # Process each APK
    for apk in apks:
        if not args.non_interactive and options is None:
            print(f"\nProcessing {apk.name}")
            options = prompt_for_options()

        # Process the APK with current options
        process_apk(apk, options, apktool_path, uber_signer_path, args)

def process_apk(apk: Path, options: Dict, apktool_path: Path, uber_signer_path: Path, args: argparse.Namespace):
    """Process a single APK with the given options."""
    # Create output directory for this APK
    output_dir = Path(args.output_dir) if args.output_dir else Path(DEFAULT_CONFIG['output_dir'])
    apk_output_dir = output_dir / apk.stem
    apk_output_dir.mkdir(parents=True, exist_ok=True)
    
    unpack_dir = apk_output_dir / 'decompiled'
    if unpack_dir.exists():
        shutil.rmtree(unpack_dir)

    run(['java', '-jar', str(apktool_path), 'decode', apk, '-o', unpack_dir])

    # Handle network security config if res/xml exists
    xml_dir = unpack_dir / 'res/xml'
    if xml_dir.exists():
        xml_path = xml_dir / 'network_security_config.xml'
        try:
            if xml_path.exists():
                orig_xml = xml_path.read_text()
            else:
                print("No network_security_config.xml found in res/xml directory.")
                if not args.non_interactive and input("Skip network security config modification? [y/n]: ").lower() == 'y':
                    xml_path = None
                else:
                    return

            if xml_path:
                mod_xml = modify_xml(xml_path, options)
                if not args.non_interactive:
                    diff(orig_xml, mod_xml)
                    if input("Apply changes? [y/n]: ").lower() != 'y':
                        print("Aborted.")
                        return
                xml_path.write_text(mod_xml)
        except Exception as e:
            print(f"Error during network security config modification: {e}")
            if not args.non_interactive and input("Skip network security config modification and continue? [y/n]: ").lower() != 'y':
                print("Aborted.")
                return
    else:
        print("No res/xml directory found - skipping network security config modification")

    patched_apk = apk_output_dir / f"{apk.stem}-patched.apk"
    run(['java', '-jar', str(apktool_path), 'build', unpack_dir, '-o', patched_apk])

    aligned_apk = apk_output_dir / f"{apk.stem}-aligned.apk"
    run(['zipalign', '-f', '-p', '4', patched_apk, aligned_apk])

    sign_cmd = ['java', '-jar', str(uber_signer_path), '--apks', aligned_apk, '--allowResign', '--overwrite']
    if args.ks:
        sign_cmd += ['--ks', args.ks, '--ksPass', args.ks_pass, '--ksAlias', args.ks_alias]
        if args.ks_alias_pass:
            sign_cmd += ['--ksKeyPass', args.ks_alias_pass]
    run(sign_cmd)

    if options.get('cleanup', True):
        shutil.rmtree(unpack_dir)

    print(f"Done processing {apk.name}")
    print(f"Output files are in: {apk_output_dir}")

if __name__ == '__main__':
    main()
