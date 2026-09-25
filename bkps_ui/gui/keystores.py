"""
keystores.py - Keystore management for the BKPS Demo Automation GUI.

Provides three classes that together allow the GUI to enumerate, parse,
and visualise Java keystores (PKCS12, JKS, UBER/BC) using the JDK's
keytool CLI and, optionally, a dynamically-compiled Java helper class
for extracting raw key/certificate bytes.

Exports:
    KeystoreEntry        - value object representing one keystore entry
    KeystoreManager      - wraps a single keystore file; runs keytool
    BKPSKeystoreConfig   - registry of named KeystoreManager instances

Dependencies:
    keytool must be on PATH (included in any JRE/JDK installation).
    javac and java are required only for extract_entry_hex().
"""

import os
import subprocess
import re
import shutil
import tempfile
from datetime import datetime
from pathlib import Path


class KeystoreEntry:
    """Value object representing a single entry parsed from a keystore.

    Populated by KeystoreManager._parse_keytool_output() and returned
    as dicts via to_dict() from KeystoreManager.list_entries().
    """
    
    def __init__(self, alias, entry_type, valid_from=None, valid_until=None, details=None):
        """Create a KeystoreEntry.

        Args:
            alias:       The keystore alias string (keytool "Alias name:" field).
            entry_type:  Entry type string, e.g. 'PrivateKeyEntry', 'TrustedCertEntry'.
            valid_from:  Certificate "Valid from" date string, or None.
            valid_until: Certificate expiry date string, or None.
            details:     Dict of additional parsed keytool fields.
        """
        self.alias = alias
        self.entry_type = entry_type  # 'PrivateKeyEntry' or 'TrustedCertEntry'
        self.valid_from = valid_from
        self.valid_until = valid_until
        self.details = details or {}
    
    def is_valid(self):
        """Return True if the certificate has not expired.

        Returns:
            True if there is no expiry date (e.g. secret key entries) or if
            the current time is before valid_until; False if expired.
        """
        if not self.valid_until:
            return True
        try:
            expiry = datetime.strptime(self.valid_until, "%b %d %H:%M:%S %Y %Z")
            return datetime.now() < expiry
        except:
            return True
    
    def to_dict(self):
        """Serialise this entry to a plain dict for use by the UI layer.

        Returns:
            Dict with keys: alias, type, valid_from, valid_until, is_valid, details.
        """
        return {
            'alias': self.alias,
            'type': self.entry_type,
            'valid_from': self.valid_from,
            'valid_until': self.valid_until,
            'is_valid': self.is_valid(),
            'details': self.details
        }


class KeystoreManager:
    """Manages a single keystore file, delegating all I/O to keytool.

    Constructing a KeystoreManager does not open the keystore; call
    list_entries() to perform the first read.  Results are cached in
    self.entries so that get_entry_details() queries stay fast.
    """
    
    def __init__(self, keystore_path, password=None, keystore_type='PKCS12', provider=None, provider_path=None):
        """Initialise the manager without opening the keystore.

        Args:
            keystore_path: Absolute path to the keystore file.
            password:      Store password (None for password-less keystores).
            keystore_type: Keystore format: 'PKCS12', 'JKS', 'UBER', 'BKS', etc.
            provider:      Fully-qualified Java provider class name or short name
                           ('BC') required for non-standard keystore types.
            provider_path: Path to the provider JAR (e.g. bcprov-jdk18on-*.jar).
        """
        self.keystore_path = keystore_path
        self.password = password
        self.keystore_type = keystore_type
        self.provider = provider
        self.provider_path = provider_path
        self.entries = []
    
    def is_accessible(self):
        """Return True if the keystore file exists and is readable by this process."""
        return os.path.exists(self.keystore_path) and os.access(self.keystore_path, os.R_OK)
    
    def list_entries(self):
        """List all entries by running ``keytool -list -v`` on the keystore file.

        Parsed results are cached in self.entries for use by get_entry_details().

        Returns:
            List of entry dicts (see KeystoreEntry.to_dict()) on success, or a
            dict {\"error\": \"...\"} describing the failure.
        """
        if not self.is_accessible():
            return {"error": f"Keystore not accessible: {self.keystore_path}"}
        
        try:
            cmd = ['keytool', '-list', '-v', '-keystore', self.keystore_path, '-storetype', self.keystore_type]
            if self.password:
                cmd.extend(['-storepass', self.password])
            if self.provider:
                cmd.extend(['-provider', self.provider])
            if self.provider_path:
                cmd.extend(['-providerpath', self.provider_path])
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0:
                return {"error": result.stderr or "Failed to read keystore"}
            
            self.entries = self._parse_keytool_output(result.stdout)
            return [entry.to_dict() for entry in self.entries]
        
        except subprocess.TimeoutExpired:
            return {"error": "Keystore read timeout (> 30s). Try again or check keystore accessibility."}
        except Exception as e:
            return {"error": str(e)}

    def extract_entry_hex(self, alias):
        """Extract a keystore entry's encoded bytes as hex.

        Works for keys/certs where provider and keystore type can load the entry.
        Returns a dict with either:
          {"alias": ..., "entry_type": "KEY"|"CERT", "hex": "..."}
        or
          {"error": "..."}
        """
        if not self.is_accessible():
            return {"error": f"Keystore not accessible: {self.keystore_path}"}
        if not alias:
            return {"error": "Alias is required"}
        if not shutil.which("javac") or not shutil.which("java"):
            return {"error": "JDK tools not found (javac/java). Install a full JDK."}

        with tempfile.TemporaryDirectory(prefix="bkps_ks_extract_") as td:
            java_file = os.path.join(td, "_KeystoreExtract.java")
            class_file = os.path.join(td, "_KeystoreExtract.class")

            java_src = """
import java.io.FileInputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;

public class _KeystoreExtract {
    public static void main(String[] args) throws Exception {
        if (args.length < 5) {
            System.out.println("ERROR: Invalid arguments");
            return;
        }

        String ksPath = args[0];
        String ksType = args[1];
        String storePass = args[2];
        String alias = args[3];
        String provider = args[4];

        if (provider != null && !provider.isEmpty()) {
            try {
                // If a provider class name is passed, instantiate and register it.
                if (provider.contains(".")) {
                    Class<?> c = Class.forName(provider);
                    Provider p = (Provider) c.getDeclaredConstructor().newInstance();
                    if (Security.getProvider(p.getName()) == null) {
                        Security.addProvider(p);
                    }
                    provider = p.getName();
                } else if ("BC".equals(provider)) {
                    // Convenience path for BC short-name.
                    Class<?> c = Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider");
                    Provider p = (Provider) c.getDeclaredConstructor().newInstance();
                    if (Security.getProvider("BC") == null) {
                        Security.addProvider(p);
                    }
                    provider = p.getName();
                }
            } catch (Throwable t) {
                System.out.println("ERROR: Failed to load provider: " + provider + " (" + t + ")");
                return;
            }
        }

        KeyStore ks;
        if (provider != null && !provider.isEmpty()) {
            ks = KeyStore.getInstance(ksType, provider);
        } else {
            ks = KeyStore.getInstance(ksType);
        }

        char[] pw = storePass.isEmpty() ? null : storePass.toCharArray();
        try (FileInputStream in = new FileInputStream(ksPath)) {
            ks.load(in, pw);
        }

        Key key = null;
        try {
            key = ks.getKey(alias, pw);
        } catch (java.security.UnrecoverableKeyException e1) {
            // Key entry password may differ from store password (e.g. BC UBER uses "").
            try {
                key = ks.getKey(alias, "".toCharArray());
            } catch (java.security.UnrecoverableKeyException e2) {
                throw e1;  // re-throw original error if fallback also fails
            }
        }
        if (key != null) {
            byte[] enc = key.getEncoded();
            if (enc == null) {
                System.out.println("ERROR: Key is not extractable (encoded bytes unavailable)");
                return;
            }
            System.out.println("ENTRY_TYPE:KEY");
            System.out.println("ENTRY_HEX:" + toHex(enc));
            return;
        }

        Certificate cert = ks.getCertificate(alias);
        if (cert != null) {
            byte[] enc = cert.getEncoded();
            System.out.println("ENTRY_TYPE:CERT");
            System.out.println("ENTRY_HEX:" + toHex(enc));
            return;
        }

        System.out.println("ERROR: Alias not found or unsupported entry type: " + alias);
    }

    private static String toHex(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b : data) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}
"""

            with open(java_file, "w", encoding="utf-8") as f:
                f.write(java_src)

            cp_parts = [td]
            if self.provider_path:
                cp_parts.append(self.provider_path)
            classpath = os.pathsep.join(cp_parts)

            c = subprocess.run(
                ["javac", "-cp", classpath, java_file],
                capture_output=True, text=True, timeout=30,
            )
            if c.returncode != 0 or not os.path.isfile(class_file):
                return {"error": f"Failed to compile extractor helper:\n{c.stdout}{c.stderr}"}

            r = subprocess.run(
                [
                    "java", "-cp", classpath, "_KeystoreExtract",
                    self.keystore_path,
                    self.keystore_type,
                    self.password or "",
                    alias,
                    self.provider or "",
                ],
                capture_output=True, text=True, timeout=30,
            )
            out = (r.stdout or "") + (r.stderr or "")

            if r.returncode != 0:
                return {"error": f"Extraction failed:\n{out}"}

            entry_type = ""
            hex_value = ""
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("ENTRY_TYPE:"):
                    entry_type = line.split(":", 1)[1].strip()
                elif line.startswith("ENTRY_HEX:"):
                    hex_value = line.split(":", 1)[1].strip().upper()
                elif line.startswith("ERROR:"):
                    return {"error": line.split(":", 1)[1].strip()}

            if not hex_value:
                return {"error": f"No hex output produced for alias '{alias}'.\n{out}"}

            return {
                "alias": alias,
                "entry_type": entry_type or "UNKNOWN",
                "hex": hex_value,
            }
    
    def get_entry_details(self, alias):
        """Return the dict for the entry matching *alias*, or None if not found.

        Requires list_entries() to have been called first so self.entries is
        populated.

        Args:
            alias: The alias string to look up.

        Returns:
            Entry dict (see KeystoreEntry.to_dict()) or None.
        """
        for entry in self.entries:
            if entry.alias == alias:
                return entry.to_dict()
        return None
    
    def _parse_keytool_output(self, output):
        """Parse the verbose stdout of ``keytool -list -v`` into KeystoreEntry objects.

        Handles two output styles emitted by different JDK versions:
        - Block format with labelled fields ("Alias name: ...", "Entry type: ...", ...).
        - Compact fallback format ("alias, date, date, EntryType,").

        Args:
            output: The full stdout string from the keytool subprocess.

        Returns:
            List of KeystoreEntry objects.
        """
        entries = []
        current_entry = None
        current_details = {}
        # Fallback format line: alias, Apr 1, 2026, SecretKeyEntry,
        fallback_re = re.compile(r'^(?P<alias>[^,]+),\s+[^,]+,\s+[^,]+,\s+(?P<etype>[^,]+),?\s*$')
        
        for line in output.split('\n'):
            line = line.strip()
            if not line:
                continue

            # Handle compact output format when keytool doesn't print Alias name:/Entry type: blocks
            m = fallback_re.match(line)
            if m:
                if current_entry:
                    current_entry.details = current_details
                    entries.append(current_entry)
                current_entry = KeystoreEntry(m.group('alias').strip(), m.group('etype').strip())
                current_details = {}
                continue
            
            # Detect new entry
            if re.match(r'^Alias name:', line):
                if current_entry:
                    current_entry.details = current_details
                    entries.append(current_entry)
                alias = line.split(':', 1)[1].strip()
                current_entry = KeystoreEntry(alias, 'Unknown')
                current_details = {}
            
            # Entry type
            elif re.match(r'^Entry type:', line):
                entry_type = line.split(':', 1)[1].strip()
                if current_entry:
                    current_entry.entry_type = entry_type
            
            # Certificate validity dates
            elif re.match(r'^Owner:', line):
                owner = line.split(':', 1)[1].strip()
                current_details['owner'] = owner
            
            elif re.match(r'^Issuer:', line):
                issuer = line.split(':', 1)[1].strip()
                current_details['issuer'] = issuer
            
            elif re.match(r'^Serial number:', line):
                serial = line.split(':', 1)[1].strip()
                current_details['serial'] = serial
            
            elif re.match(r'^Valid from:', line):
                # Common format: "Valid from: ... until: ..."
                tail = line.split(':', 1)[1].strip()
                if ' until: ' in tail:
                    valid_from, valid_until = tail.split(' until: ', 1)
                    valid_from = valid_from.strip()
                    valid_until = valid_until.strip()
                    if current_entry:
                        current_entry.valid_from = valid_from
                        current_entry.valid_until = valid_until
                    current_details['valid_from'] = valid_from
                    current_details['valid_until'] = valid_until
                else:
                    valid_from = tail
                    if current_entry:
                        current_entry.valid_from = valid_from
                    current_details['valid_from'] = valid_from
            
            elif re.match(r'^until:', line):
                valid_until = line.split(':', 1)[1].strip()
                if current_entry:
                    current_entry.valid_until = valid_until
                current_details['valid_until'] = valid_until

            elif re.match(r'^Secret key algorithm:', line):
                current_details['secret_key_algorithm'] = line.split(':', 1)[1].strip()

            elif re.match(r'^Key size:', line):
                current_details['key_size'] = line.split(':', 1)[1].strip()
            
            # Certificate fingerprints
            elif re.match(r'^(SHA1|SHA256|MD5) Fingerprint:', line):
                parts = line.split(':', 1)
                fp_type = parts[0].strip()
                fingerprint = parts[1].strip() if len(parts) > 1 else ''
                current_details[f'{fp_type}_fingerprint'] = fingerprint
            
            elif re.match(r'^Signature algorithm:', line):
                sig_algo = line.split(':', 1)[1].strip()
                current_details['signature_algorithm'] = sig_algo
            
            elif re.match(r'^Subject Public Key Info:', line):
                # Next line usually has algorithm details
                current_details['subject_public_key'] = 'See details'
        
        # Add the last entry
        if current_entry:
            current_entry.details = current_details
            entries.append(current_entry)
        
        return entries


class BKPSKeystoreConfig:
    """Registry mapping friendly names to KeystoreManager instances.

    Provides a centralised store for all keystores discovered or manually
    added by the Keystore Viewer dialog.  Keystores can be loaded from a
    config dict at construction time or added dynamically via add_keystore().
    """
    
    def __init__(self, config_dict=None):
        """
        Initialize with config dictionary
        Expected format:
        {
            'keystores': {
                'bkps_keystore': {
                    'path': '/path/to/keystore.p12',
                    'type': 'PKCS12',
                    'password': 'password'
                }
            }
        }
        """
        self.keystores = {}
        if config_dict and 'keystores' in config_dict:
            self._load_config(config_dict['keystores'])
    
    def _load_config(self, keystores_config):
        """Instantiate KeystoreManager objects from a raw keystores config dict.

        Args:
            keystores_config: The value of config_dict['keystores']  — a mapping
                              of name → {path, password, type} dicts.
        """
        for name, config in keystores_config.items():
            ks = KeystoreManager(
                keystore_path=config.get('path'),
                password=config.get('password'),
                keystore_type=config.get('type', 'PKCS12')
            )
            self.keystores[name] = ks
    
    def add_keystore(self, name, path, password=None, keystore_type='PKCS12', provider=None, provider_path=None):
        """Register a new keystore under *name*, replacing any existing entry.

        Args:
            name:          Friendly display name shown in the UI combo box.
            path:          Absolute path to the keystore file.
            password:      Store password (None for no password).
            keystore_type: Keystore format string (default 'PKCS12').
            provider:      Java security provider class name or short name.
            provider_path: Path to the provider JAR file.
        """
        ks = KeystoreManager(path, password, keystore_type, provider, provider_path)
        self.keystores[name] = ks
    
    def get_keystore(self, name):
        """Return the KeystoreManager registered under *name*, or None."""
        return self.keystores.get(name)
    
    def get_all_keystores(self):
        """Return the full {name: KeystoreManager} mapping dict."""
        return self.keystores
    
    def list_all_entries(self):
        """Enumerate entries from every registered keystore.

        Returns:
            Dict mapping each keystore name to the result of list_entries()
            for that keystore (either a list of entry dicts or an error dict).
        """
        all_entries = {}
        for name, ks in self.keystores.items():
            entries = ks.list_entries()
            if isinstance(entries, list):
                all_entries[name] = entries
            else:
                all_entries[name] = entries  # error dict
        return all_entries
