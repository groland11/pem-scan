#!/usr/bin/env python3

import argparse
from datetime import datetime, timedelta
import logging
import os
import re
import sys

from cryptography import x509
from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives.serialization import load_pem_public_key


class LogFilter(logging.Filter):
    def filter(self, record):
        return record.levelno in (logging.DEBUG, logging.WARNING, logging.INFO)


def parseargs():
    """Process command line arguments"""
    parser = argparse.ArgumentParser(description="Script description")
    parser.add_argument("-e", "--expires", type=int,
                        help="check if certificate expires in n days or less")
    parser.add_argument("-d", "--debug", action="store_true",
                        help="generate additional debug information")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="increase output verbosity")
    parser.add_argument("filename", type=str,
                        help="file or directory containing onw or more x509 certificates in PEM format")
    parser.add_argument("-V", "--version", action="version", version="1.0.0")
    return parser.parse_args()


def get_logger(debug: bool = False) -> logging.Logger:
    """Retrieve logging object"""
    logger = logging.getLogger(__name__)
    if debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    h1 = logging.StreamHandler(sys.stdout)
    h1.setLevel(logging.DEBUG)
    h1.setFormatter(logging.Formatter(fmt="%(levelname)s: %(message)s"))
    h1.addFilter(LogFilter())

    h2 = logging.StreamHandler(sys.stdout)
    h2.setFormatter(logging.Formatter(fmt="%(levelname)s: %(message)s"))
    h2.setLevel(logging.ERROR)

    logger.addHandler(h1)
    logger.addHandler(h2)

    return logger


class CertStore:
    """
    Base class for different certificate stores, e.g. FileCertStore, DirCertStore, etc.
    """
    # Types of checks that can be performed on certificates
    CHECK_EXPIRES = 0

    def __init__(self, verbose: bool = False, debug: bool = False):
        self._verbose = verbose
        self._debug = debug
        self._logger = logging.getLogger(__name__)
        self._cert_list = {}
        self._current_cert: x509.Certificate = None
        self._check_list = {}

    def check_expires(self, expires: int = 0) -> bool:
        """
        Check if current certificate expires in <expires> days
        Errors will be written to stdout
        """
        diff_delta = self._current_cert.not_valid_after - datetime.now()
        if diff_delta < timedelta(days=expires):
            self._logger.error(f"FAIL: Certificate expires in {diff_delta.days} days \
({self._current_cert.not_valid_after.strftime('%Y-%m-%d')})")
            return False

        return True

    def enable_check(self, check_type: int, check_param: object) -> None:
        """
        Enabble individual checks on certificate data
        Checks to be performed are all stored in a dictionary
        """
        if check_type == CertStore.CHECK_EXPIRES:
            self._check_list[self.check_expires] = check_param

    def run_checks(self) -> bool:
        """
        Run all enabled checks
        """
        ret = True

        if self._current_cert is None:
            self._logger.warning("Unable to perform checks: Missing certificate")
            return False

        # Loop through all check functions ...
        for check_func, check_param in self._check_list.items():
            # self._logger.debug(f"Running {check_func.__name__}({check_param}) ...")
            if not check_func(check_param):
                ret = False

        return ret

    def store_cert(self, cert: x509.Certificate) -> None:
        """
        Store certificate in dictionary for later use
        Dictionary key is either SubjectKeyIdentifier or - if not present - subject
        """
        try:
            self._current_cert = cert
            ext_ski = cert.extensions.get_extension_for_oid(x509.OID_SUBJECT_KEY_IDENTIFIER)
        except x509.extensions.ExtensionNotFound:
            key = cert.subject.rfc4514_string()
        else:
            key = ext_ski.value.digest.hex()

        if self._cert_list.get(key) is None:
            self._cert_list[key] = cert
        else:
            raise ValueError(f"Duplicate certificate for \"{self.scan_subject(cert.subject.rfc4514_string()).get('CN')}\"")

    def scan_subject(self, subject: str) -> dict:
        """Convert path components of subject line to dictionary (OU, O, C, CN, ST, L)"""
        sdict = {}

        subject = subject.replace("\\,", "")  # Colons in values should be escaped and will be ignored
        for part in subject.split(","):
            try:
                (key, value) = part.split('=', maxsplit=1)
            except ValueError:
                # If there is still a colon in the value part, there will be no '=' sign
                # Therefore ignore everything after the colon
                continue
            sdict[key] = value

        return sdict

    def scan_pem(self, pem: str, linenr: int = 0) -> x509.Certificate:
        """
        Convert text lines in PEM format into a X509 certificate object

        Following information will be written to stdout:
        - Subject
        - Issuer
        - Valid from
        - Valid until
        - SubjectAlternativeName
        - SubjectKeyIdentifier
        - AuthorityKeyIdentifier
        - BasicConstraints
        """
        certificate = x509.load_pem_x509_certificate(pem.encode(), default_backend())

        # Print Common Name (CN)
        subject = certificate.subject.rfc4514_string()
        sdict = self.scan_subject(subject)
        print(f'{linenr:>5}: {sdict.get("CN")}')
        self._logger.debug(subject)

        if self._verbose:
            # Print rest of subject line without CN
            subject_rest = ""
            for key in ('O', 'OU', 'C'):
                subject_rest += f"{key}={sdict[key]}," if sdict.get(key) else ""
            if len(subject_rest) > 0:
                print(f"  Subject: {subject_rest[:-1]}")

            # Certificate issuer
            issuer = certificate.issuer.rfc4514_string()
            issuer_dict = self.scan_subject(issuer)
            print(f'  Issuer CN: {issuer_dict.get("CN")}')

            issuer_rest = ""
            for key in ('O', 'OU', 'C'):
                issuer_rest += f"{key}={sdict[key]}," if sdict.get(key) else ""
            if len(issuer_rest) > 0:
                print(f"  Issuer: {subject_rest[:-1]}")

            # Valid from / until
            print(f"  Not before: {certificate.not_valid_before}")
            print(f"  Not after: {certificate.not_valid_after}")

            # Extension: SubjectAlternativeName
            try:
                ext_san = certificate.extensions.get_extension_for_oid(x509.OID_SUBJECT_ALTERNATIVE_NAME)
                output = ','.join(ext_san.value.get_values_for_type(x509.DNSName))
                if len(output) > 0:
                    print(f"  SubjectAlternativeName: {output}")
            except x509.extensions.ExtensionNotFound as e:
                self._logger.debug(f"SAN: {e}")

            # Extension: SubjectKeyIdentifier
            try:
                ext_ski = certificate.extensions.get_extension_for_oid(x509.OID_SUBJECT_KEY_IDENTIFIER)
                print(f"  SubjectKeyIdentifier: {ext_ski.value.digest.hex()}")
            except x509.extensions.ExtensionNotFound as e:
                self._logger.debug(f"SubjectKeyIdentifier: {e}")

            # Extension: AuthorityKeyIdentifier
            try:
                ext_aki = certificate.extensions.get_extension_for_oid(x509.OID_AUTHORITY_KEY_IDENTIFIER)
                print(f"  AuthorityKeyIdentifier: {ext_aki.value.key_identifier.hex()}")
            except x509.extensions.ExtensionNotFound as e:
                self._logger.debug(f"AuthorityKeyIdentifier: {e}")

            # Extension: BasicConstraints
            try:
                ext_bc = certificate.extensions.get_extension_for_oid(x509.OID_BASIC_CONSTRAINTS)
                print(f"  BasicConstraints: CA={ext_bc.value.ca},Critical={ext_bc.critical}")
            except x509.extensions.ExtensionNotFound as e:
                self._logger.debug(f"BasicConstraints: {e}")

        return certificate

    def scan(self) -> None:
        pass


class FileCertStore(CertStore):
    """One or more certificates are stored in a single file"""
    def __init__(self, filename: str, verbose: bool = False, debug: bool = False):
        super().__init__(verbose=verbose, debug=debug)
        self.__filename = filename

    def scan(self) -> bool:
        """Scan current file for one or more PEM encoded certificates"""
        pem = ""
        is_pem = False
        linenr = 0
        beginnr = 0
        ret = True

        try:
            with open(self.__filename, "r") as pem_file:
                print(f"{self.__filename}")
                for line in pem_file.readlines():
                    linenr += 1

                    # Begin of certificate
                    if re.match(r"^-----BEGIN CERTIFICATE-----$", line.strip()):
                        pem += line
                        beginnr = linenr
                        is_pem = True
                        continue

                    # Continuation line
                    if is_pem:
                        pem += line

                        if re.match(r"^-----END CERTIFICATE-----$", line.strip()):
                            # End of certificate
                            is_pem = False
                            try:
                                certificate = self.scan_pem(pem, linenr=beginnr)
                                if certificate:
                                    # We found a valid certificate
                                    self.store_cert(certificate)
                                    ret = self.run_checks()
                                    if not ret:
                                        if not ret:
                                            self._logger.error(
                                                f"Failed checks for \
{self.scan_subject(certificate.subject.rfc4514_string()).get('CN')} ({self.__filename})")
                            except ValueError as e:
                                self._logger.warning(f"{self.__filename}: {e}")
                            except Exception as e:
                                self._logger.error(f"{e}")
                                ret = False
                            finally:
                                pem = ""

                        continue

        except (FileNotFoundError, UnicodeDecodeError, PermissionError) as e:
            # Broken symbolic link, not a text file
            self._logger.error(f"{e}")
            ret = False

        return ret


def main():
    """Main program flow"""
    cert_store_list = []
    args = parseargs()
    # logger = get_logger(args.debug)
    ret = True

    # Scan a single file
    if os.path.isfile(args.filename):
        file_store = FileCertStore(args.filename, verbose=args.verbose, debug=args.debug)
        if args.expires is not None:
            file_store.enable_check(check_type=FileCertStore.CHECK_EXPIRES, check_param=args.expires)
        ret = file_store.scan()
        cert_store_list.append(file_store)

    # Scan a directory and all subdirectories
    if os.path.isdir(args.filename):
        for root, dir, files in os.walk(args.filename):
            for name in files:
                if re.match(r".*\.(pem|cert|crt|key)$", name, flags=re.IGNORECASE):
                    file_store = FileCertStore(os.path.join(root, name), verbose=args.verbose, debug=args.debug)
                    if args.expires is not None:
                        file_store.enable_check(check_type=FileCertStore.CHECK_EXPIRES, check_param=args.expires)
                    if not file_store.scan():
                        ret = False
                    cert_store_list.append(file_store)

    exit(int(ret))


if __name__ == '__main__':
    main()
