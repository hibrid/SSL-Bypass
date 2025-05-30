# APK Rebuild Tools

This repository contains tools for modifying Android APKs to enable HTTPS traffic inspection and debugging. The primary use case is bypassing SSL certificate pinning to allow inspection of encrypted traffic using tools like Charles Proxy or Fiddler.

## Use Cases

1. **HTTPS Traffic Inspection**
   - Debug and analyze encrypted traffic from Android apps
   - Research app behavior and API interactions
   - Test security implementations
   - Monitor network activity during development

2. **APK Modification**
   - Modify app configurations
   - Add custom certificates
   - Change network security settings
   - Repackage and resign apps

3. **Emulator Support**
   - Works with BlueStacks 5 (requires ProxyCap)
   - Works with MuMu Player (direct proxy configuration)
   - Supports other Android emulators

## Manual Process

To manually enable HTTPS inspection of an Android app, you would need to:

1. **Prepare the APK**
   - Decompile the APK using Apktool
   - Locate or create `network_security_config.xml`
   - Modify the config to trust user certificates
   - Update AndroidManifest.xml to reference the config
   - Rebuild and sign the APK

2. **Install Certificate**
   - Generate hash of your proxy's root certificate
   - Rename certificate to `<hash>.0`
   - Make system partition writable (for emulators)
   - Copy certificate to `/system/etc/security/cacerts/`

3. **Configure Proxy**
   - For BlueStacks 5:
     1. Install ProxyCap
     2. Configure ProxyCap to route traffic to Fiddler/Charles
     3. Set ProxyCap as system proxy
   - For MuMu Player:
     1. Go to WiFi settings
     2. Use manual proxy configuration
     3. Point directly to Fiddler/Charles

## How Our Scripts Help

Our scripts automate the manual process with different levels of control and features:

### apk-rebuild.py
The original comprehensive tool that:
- Automates the entire APK modification process
- Handles certificate installation
- Supports split APKs and AAB files
- Provides detailed logging
- Offers interactive XML modification
- Supports batch processing via config files

### apk-rebuild-lean.py
A streamlined version that:
- Focuses on essential APK modification
- Provides faster execution
- Minimal user interaction
- Basic certificate handling
- Best for simple, quick modifications

### apk-interactive.py
A balanced version that:
- Combines best features of both scripts
- Adds improved error handling
- Supports both interactive and automated modes
- Handles directory scanning for multiple APKs
- Provides better certificate pinning management
- Offers config file support

## Emulator-Specific Instructions

### BlueStacks 5
1. Use any of our scripts to modify the APK
2. Install ProxyCap
3. Configure ProxyCap:
   ```
   Proxy Type: HTTP
   Host: 127.0.0.1
   Port: 8888 (or your proxy port)
   ```
4. Set ProxyCap as system proxy
5. Install the modified APK

### MuMu Player
1. Use any of our scripts to modify the APK
2. Make system partition writable:
   ```bash
   adb root
   adb remount
   ```
3. Configure proxy in MuMu:
   - Settings > WiFi > Long press current network
   - Modify network > Advanced options
   - Proxy: Manual
   - Host: 127.0.0.1
   - Port: 8888 (or your proxy port)
4. Install the modified APK

## apk-rebuild.py

The original script that provides a comprehensive set of features for APK modification:

- Full interactive mode for XML modifications
- Certificate pinning management
- User certificate installation
- Detailed logging and colorized output
- Support for split APKs
- Config file support for batch processing
- Tool management system

### Command Line Usage
```bash
python3 apk-rebuild.py [options] <apk_file>
```

#### Positional Arguments
- `apk_file`: Path to .apk, .aab, or .xapk file for rebuilding

#### Options
- `-h, --help`: Show help message and exit
- `-v, --version`: Show program's version number and exit
- `-i, --install`: Install the rebuilt .apk file(s) via adb
- `--pause`: Pause script execution before building the output .apk
- `-p, --preserve`: Preserve the unpacked content of the .apk file(s)
- `-r, --remove`: Remove the source file after rebuilding
- `-o OUTPUT, --output OUTPUT`: Output .apk file name or directory path (for .xapk)
- `--no-src`: Use --no-src option when decompiling via apktool
- `--only-main-classes`: Use --only-main-classes option when decompiling
- `--ks KS`: Use custom .keystore file for .aab decoding and .apk signing
- `--ks-pass KS_PASS`: Password of the custom keystore
- `--ks-alias KS_ALIAS`: Key (alias) in the custom keystore
- `--ks-alias-pass KS_ALIAS_PASS`: Password for key (alias) in the custom keystore

#### Examples
```bash
# Patch AAB file and preserve unpacked content
python3 apk-rebuild.py input.aab --preserve

# Patch APK, remove source, and install on device
python3 apk-rebuild.py input.apk -r -i

# Use custom keystore for signing
python3 apk-rebuild.py input.apk --ks my.keystore --ks-pass password --ks-alias myalias
```

## apk-rebuild-lean.py

A streamlined version focused on essential functionality:

- Minimal dependencies
- Faster execution
- Basic XML modification
- Simple certificate handling
- No config file support
- No split APK handling

### Command Line Usage
```bash
python3 apk-rebuild-lean.py [options] <apk_file>
```

#### Positional Arguments
- `apk_file`: Path to .apk file for rebuilding

#### Options
- `-h, --help`: Show help message and exit
- `--interactive`: Enable interactive XML modification
- `--preserve`: Preserve unpacked content
- `--ks KS`: Use custom keystore file
- `--ks-pass KS_PASS`: Keystore password
- `--ks-alias KS_ALIAS`: Keystore alias
- `--ks-alias-pass KS_ALIAS_PASS`: Alias password

#### Examples
```bash
# Basic APK modification
python3 apk-rebuild-lean.py input.apk

# Interactive mode with preserved content
python3 apk-rebuild-lean.py input.apk --interactive --preserve

# Use custom keystore
python3 apk-rebuild-lean.py input.apk --ks my.keystore --ks-pass password
```

## apk-interactive.py

A new version that combines the best features of both scripts while adding new capabilities:

- Interactive mode with improved error handling
- Non-interactive mode for automation
- Config file support
- Directory scanning for APKs
- Improved certificate handling
- Better error recovery
- Support for both single and split APKs

### Command Line Usage
```bash
python3 apk-interactive.py [options] [path]
```

#### Positional Arguments
- `path`: Optional path to APK file, directory containing APKs, or config file

#### Options
- `-h, --help`: Show help message and exit
- `--config`: Path to config file
- `--non-interactive`: Run in non-interactive mode using defaults
- `--ks KS`: Use custom keystore file
- `--ks-pass KS_PASS`: Keystore password
- `--ks-alias KS_ALIAS`: Keystore alias

#### Config File Format
```json
{
    "files": [
        {
            "path": "base.apk",
            "options": {
                "allow_cleartext": true,
                "trust_system": true,
                "trust_user": true,
                "remove_pins": true,
                "cleanup": true,
                "non_interactive": false,
                "ks": null,
                "ks_pass": null,
                "ks_alias": null,
                "ks_alias_pass": null
            }
        },
        {
            "path": "split_config.xxxhdpi.apk",
            "options": {
                "cleanup": true
            }
        }
    ],
    "continue_on_missing": true,
    "search_path": ".",
    "allow_cleartext": true,
    "trust_system": true,
    "trust_user": true,
    "remove_pins": true,
    "cleanup": true,
    "non_interactive": false,
    "ks": null,
    "ks_pass": null,
    "ks_alias": null,
    "ks_alias_pass": null
}
```

The config file supports both global options and per-file options. Global options will be applied to all files unless overridden by file-specific options.

##### Global Options
- `continue_on_missing`: Whether to continue processing if a file is not found
- `search_path`: Base directory for finding APK files
- `allow_cleartext`: Allow cleartext traffic
- `trust_system`: Trust system certificates
- `trust_user`: Trust user certificates
- `remove_pins`: Remove certificate pins
- `cleanup`: Clean up temporary files after processing
- `non_interactive`: Run in non-interactive mode
- `ks`: Path to keystore file
- `ks_pass`: Keystore password
- `ks_alias`: Keystore alias
- `ks_alias_pass`: Keystore alias password

##### Per-File Options
Each file in the `files` array can have its own `options` object that overrides the global options. The available options are the same as the global options.

##### Config File Examples

1. **Basic Per-File Override**
```json
{
    "files": [
        {
            "path": "base.apk",
            "options": {
                "allow_cleartext": false,
                "trust_system": false
            }
        }
    ],
    "allow_cleartext": true,
    "trust_system": true
}
```
In this example, `base.apk` will use `allow_cleartext: false` and `trust_system: false`, while inheriting other options from global settings.

2. **Different Keystores Per File**
```json
{
    "files": [
        {
            "path": "base.apk",
            "options": {
                "ks": "/path/to/debug.keystore",
                "ks_pass": "android",
                "ks_alias": "androiddebugkey"
            }
        },
        {
            "path": "split_config.arm64.apk",
            "options": {
                "ks": "/path/to/release.keystore",
                "ks_pass": "release123",
                "ks_alias": "release"
            }
        }
    ],
    "ks": "/path/to/default.keystore"
}
```
Each APK uses its own keystore configuration, overriding the global keystore setting.

3. **Selective Interactive Mode**
```json
{
    "files": [
        {
            "path": "base.apk",
            "options": {
                "non_interactive": false,
                "remove_pins": true
            }
        },
        {
            "path": "split_config.xxxhdpi.apk",
            "options": {
                "non_interactive": true,
                "cleanup": false
            }
        }
    ],
    "non_interactive": true,
    "cleanup": true
}
```
`base.apk` runs in interactive mode with pin removal, while `split_config.xxxhdpi.apk` runs non-interactively and preserves its files.

4. **Minimal Per-File Configuration**
```json
{
    "files": [
        {
            "path": "base.apk"
        },
        {
            "path": "split_config.arm64.apk",
            "options": {
                "cleanup": false
            }
        }
    ],
    "allow_cleartext": true,
    "trust_system": true,
    "trust_user": true,
    "remove_pins": true,
    "cleanup": true
}
```
`base.apk` uses all global options, while `split_config.arm64.apk` only overrides the cleanup setting.

#### Examples
```bash
# Process single APK
python3 apk-interactive.py input.apk

# Process directory of APKs
python3 apk-interactive.py ./apks/

# Use config file
python3 apk-interactive.py --config config.json

# Non-interactive mode
python3 apk-interactive.py input.apk --non-interactive

# Use custom keystore
python3 apk-interactive.py input.apk --ks my.keystore --ks-pass password
```

## Comparison and Recommendations

### When to use apk-rebuild.py
- When you need the most comprehensive feature set
- For complex certificate pinning scenarios
- When working with split APKs
- When you need detailed logging and colorized output
- For batch processing with config files

### When to use apk-rebuild-lean.py
- For simple, quick modifications
- When you don't need interactive features
- When working with single APKs only
- When you want minimal dependencies
- For automated scripts where speed is important

### When to use apk-interactive.py
- When you need a balance of features and usability
- For both interactive and automated workflows
- When working with multiple APKs in a directory
- When you need better error handling
- For scenarios requiring certificate pinning with retry options
- When you need config file support but don't need all features of apk-rebuild.py

## Common Features Across All Scripts

All scripts share these core features:
- APK decoding and rebuilding
- Network security config modification
- Certificate handling
- APK signing
- Tool management (automatic download of required tools)

## Requirements

- Python 3.6+
- Java Runtime Environment
- Required tools (automatically downloaded):
  - Apktool
  - Uber APK Signer
  - Zipalign (from Android SDK)

## Installation

1. Clone the repository
2. Ensure you have Python 3.6+ and Java installed
3. Run any of the scripts - they will automatically download required tools

## Notes

- All scripts store tools in `~/.config/apk-rebuild/`
- The scripts will automatically download required tools if they're missing
- For best results with split APKs, process base.apk first
- Certificate installation requires root access on the target device

# android-ssl-pinning-bypass
A python script (previously `bash`) that prepares Android APK (or AAB, XAPK) for HTTPS traffic inspection.

## Disclaimer
1. This script is not a "silver bullet" and even after using it you still might not be able to capture or decrypt the HTTPS traffic on Android. Learn tip #2 from the [Tips section](https://github.com/ilya-kozyr/android-ssl-pinning-bypass#tips).
2. The script is not fully tested yet upon migration to python. This point will be removed once the script will be tested.

## Features
The script allows to bypass SSL pinning on Android >= 7 via rebuilding the APK file and making the user credential storage trusted. After processing the output APK file is ready for HTTPS traffic inspection.

If an AAB file provided the script creates a universal APK and processes it. If a XAPK file provided the script unzips it and processes every APK file.
## Compatibility

Works on macOS, Linux and Windows.

[NEEDS TESTING] The performance on the Windows probably will be a few times (~3.5) lower than in macOS / Linux (`apktool` takes longer time to decode the APK).
## How the script works?

It:
- first of all checks if all the necessary tools are available and downloads it if it's not (except `java`);
- decodes the AAB file to APK file via `bundletool` (if AAB file provided) or unzips the XAPK file (in case of XAPK);
- decodes the APK file using `apktool`;
- patches (or creates if the file is missing) the app's `network_security_config.xml` to make user credential storage as trusted;
- encodes the new APK file via `apktool`;
- signs the patched APK file(s) via `uber-apk-signer`.

Optionally the script allow to:
- use the specific keystore for signing the output APK (by default the debug keystore is used);
- install the patched APK file(s) directly to the device via `adb`;
- preserve unpacked content of the input APK file(s);
- remove the source file (APK / AAB / XAPK) after patching;
- pause the script execution before the encoding the output APK file(s) in case you need to make any actions manually.

Root access is not required.
## Requirements
Install the tools from the list below:

- python >= 3.9
- pip
- java >= 8
- adb - can be installed with [Android Studio](https://developer.android.com/studio) (recommended) or [standalone package of the SDK platform tools](https://developer.android.com/studio/releases/platform-tools) (don't forget to add the path to the `adb` to the PATH environment variable)

The tools below will be downloaded by the script in case it's missing:
- [bundletool](https://github.com/google/bundletool/releases)
- [apktool](https://github.com/iBotPeaches/Apktool/releases)
- [uber-apk-signer](https://github.com/patrickfav/uber-apk-signer/releases)
## Usage
Preconditions:
1. Clone the repository
2. Execute the command `pip3 install -r requirements.txt` to install the required python modules

The script can be launched like
```
python3 /path/to/the/script/apk-rebuild.py
```

Execute  `python3 apk-rebuild.py -h` (or `python3 apk-rebuild.py --help`) to print the usage manual.
```
usage: apk-rebuild.py [-h] [-v] [-i] [--pause] [-p] [-r] [-o OUTPUT] [--no-src] [--only-main-classes] [--ks KS]
                      [--ks-pass KS_PASS] [--ks-alias KS_ALIAS] [--ks-alias-pass KS_ALIAS_PASS]
                      file

The script allows to bypass SSL pinning on Android >= 7 via rebuilding the APK file 
and making the user credential storage trusted. After processing the output APK file 
is ready for HTTPS traffic inspection.

positional arguments:
  file                  path to .apk, .aab or .xapk file for rebuilding

options:
  -h, --help            show this help message and exit
  -v, --version         show program's version number and exit
  -i, --install         install the rebuilded .apk file(s) via adb
  --pause               pause the script execution before the building the output .apk
  -p, --preserve        preserve the unpacked content of the .apk file(s)
  -r, --remove          remove the source file (.apk, .aab or .xapk) after the rebuilding
  -o OUTPUT, --output OUTPUT
                        output .apk file name or output directory path (for .xapk source file)
  --no-src              use --no-src option when decompiling via apktool
  --only-main-classes   use --only-main-classes option when decompiling via apktool
  --ks KS               use custom .keystore file for .aab decoding and .apk signing
  --ks-pass KS_PASS     password of the custom keystore
  --ks-alias KS_ALIAS   key (alias) in the custom keystore
  --ks-alias-pass KS_ALIAS_PASS
                        password for key (alias) in the custom keystore
```

For rebuilding the APK file use script with argument(s). The examples are below:
- patch the AAB file and do not delete the unpacked APK file content

  ```
  python3 apk-rebuild.py input.aab --preserve
  ```

- patch the APK file, remove the source APK file after patching and install the patched APK file on the Android-device

  ```
  python3 apk-rebuild.py input.apk -r -i
  ```

The path to the source file must be specified as the first argument.



## Tips
1. For easy capturing HTTPS traffic from development builds you can ask your developer to add the `<debug-overrides>` element to `the network_security_config.xml` (and add the `android:networkSecurityConfig` property to the `application` element in the `AndroidManifest.xml` of course): [https://developer.android.com/training/articles/security-config#debug-overrides](https://developer.android.com/training/articles/security-config#debug-overrides).
2. Learn [https://blog.nviso.eu/2020/11/19/proxying-android-app-traffic-common-issues-checklist/](https://blog.nviso.eu/2020/11/19/proxying-android-app-traffic-common-issues-checklist/), there are a lot of useful info about traffic capture on Android.
## Contribution
For bug reports, feature requests or discussing an idea, open an issue [here](https://github.com/ilya-kozyr/android-ssl-pinning-bypass/issues).
## Credits
Many thanks to:
- [Connor Tumbleson](https://github.com/iBotPeaches) for [apktool](https://github.com/iBotPeaches/Apktool)
- [Patrick Favre-Bulle](https://github.com/patrickfav) for [uber-apk-signer](https://github.com/patrickfav/uber-apk-signer)
- [Google](https://github.com/google) for [bundletool](https://github.com/google/bundletool)
