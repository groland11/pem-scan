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

try:
    from colorama import init, Back, Cursor, Fore, Style
except ImportError:
    from collections import UserString

    class ColoramaMock(UserString):
        def __call__(self, *args, **kwargs):
            return self
        def __getattr__(self, key):
            return self

    init = ColoramaMock("")
    Back = Cursor = Fore = Style = ColoramaMock("")


class LogFilter(logging.Filter):
    def filter(self, record):
        return record.levelno in (logging.DEBUG, logging.WARNING, logging.INFO)


def parseargs():
    """Process command line arguments"""
    parser = argparse.ArgumentParser(description="Check single file or directory for one or more X509 PEM certificates")
    parser.add_argument("-e", "--expires", type=int,
                        help="check if certificate expires in n days or less")
    parser.add_argument("-c", "--chain", action="store_true",
                        help="check certificate chain")
    parser.add_argument("--caa", action="store_true",
                        help="check CAA record in DNS")
    parser.add_argument("--regex", type=str,
                        help="filter CN in subject by regex expression (only for directories)")
    parser.add_argument("--ski", type=str,
                        help="filter by subject key identifier (only for directories)")
    parser.add_argument("--aki", type=str,
                        help="filter by authority key identifier (only for directories)")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="only display error messages and certificate file names")
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
    CHECK_CAA = 1

    def __init__(self, quiet: bool = False, verbose: bool = False, debug: bool = False):
        self._quiet = quiet
        self._verbose = verbose
        self._debug = debug
        self._logger = logging.getLogger(__name__)
        self.cert_list = {}
        self._current_cert: x509.Certificate = None
        self._check_list = {}
        self.filter_cn = None
        self.filter_ski = None
        self.filter_aki = None

    def set_filter(self, cn: str = None, ski: str = None, aki: str = None) -> None:
        """Set filter for certificates by subject or attributes"""
        self.filter_cn = cn
        self.filter_ski = None if ski is None else ski.replace(":", "").lower()
        self.filter_aki = None if aki is None else aki.replace(":", "").lower()

    def has_filter(self) -> bool:
        """Returns True if any filter has been set"""
        if self.filter_cn is not None or \
                self.filter_ski is not None or \
                self.filter_aki is not None:
            return True
        else:
            return False

    def is_rootca(self, cert: x509.Certificate) -> bool:
        """
        Check if certificate is Root CA:
        - Ommit check for Basic Constraint (assume that self-signed certificates are also some sort of Root Ca)
        - Next check if AKI is identical to SKI
        - If AKI of SKI is missing, compare issuer to certificate name
        """
        # Check BasicConstraint
        try:
            ext_bc = cert.extensions.get_extension_for_oid(x509.OID_BASIC_CONSTRAINTS)
        except x509.extensions.ExtensionNotFound:
            # Assume that Root CAs must have Basic Constraint set
            return False

        #if ext_bc.value.ca == False:
        #    return False

        # Check if AKI == SKI
        try:
            ext_ski = cert.extensions.get_extension_for_oid(x509.OID_SUBJECT_KEY_IDENTIFIER)
            ext_aki = cert.extensions.get_extension_for_oid(x509.OID_AUTHORITY_KEY_IDENTIFIER)
        except x509.extensions.ExtensionNotFound:
            pass
        else:
            if ext_ski.value.digest.hex() == ext_aki.value.key_identifier.hex():
                return True
            else:
                return False

        # Check if issuer == certificate name
        subject_dict = self.scan_subject(cert.subject.rfc4514_string())
        # Some certificates do not have a CN set in subject. Use OU instead.
        subject_name = subject_dict.get("CN") if subject_dict.get("CN") is not None else subject_dict.get("OU")

        issuer_dict = self.scan_subject(cert.issuer.rfc4514_string())
        issuer_name = issuer_dict.get("CN") if issuer_dict.get("CN") is not None else issuer_dict.get("OU")

        if issuer_name == subject_name:
            return True

        return False

    def check_expires(self, expires: int = 0) -> bool:
        """
        Check if current certificate expires in <expires> days
        Errors will be written to stdout
        """
        diff_delta = self._current_cert.not_valid_after - datetime.now()
        if diff_delta < timedelta(days=expires):
            self._logger.error(f"{Fore.LIGHTWHITE_EX}{Back.RED}FAIL{Style.RESET_ALL}: Certificate expires in {diff_delta.days} days \
({self._current_cert.not_valid_after.strftime('%Y-%m-%d')})")
            return False

        return True

    def check_caa(self, param=0) -> bool:
        """
        Check if CAA record in DNS conforms to issuer attribute in certificate
        Errors will be written to stdout
        """
        pass

    def enable_check(self, check_type: int, check_param: object) -> None:
        """
        Enabble individual checks on certificate data
        Checks to be performed are all stored in a dictionary
        """
        if check_type == CertStore.CHECK_EXPIRES:
            self._check_list[self.check_expires] = check_param
        if check_type == CertStore.CHECK_CAA:
            self._check_list[self.check_caa] = None

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

        if self.cert_list.get(key) is None:
            self.cert_list[key] = cert
        else:
            raise ValueError(
                f'Duplicate certificate for {self.scan_subject(cert.subject.rfc4514_string()).get("CN")}')

    def scan_subject(self, subject: str) -> dict:
        """Convert path components of subject line to dictionary (OU, O, C, CN, ST, L)"""
        sdict = {}

        subject = subject.replace('\\,', "")  # Colons in values should be escaped and will be ignored
        for part in subject.split(","):
            try:
                (key, value) = part.split('=', maxsplit=1)
            except ValueError:
                # If there is still a colon in the value part, there will be no '=' sign
                # Therefore ignore everything after the colon
                continue
            sdict[key] = value

        return sdict

    def scan_pem(self, pem: str, linenr: int = 0) -> (x509.Certificate, str):
        """
        Convert text lines in PEM format into a X509 certificate object

        Following information will be written to stdout (if not quiet):
        - Subject
        Following information will be written additionally to stdout (if verbose):
        - Issuer
        - Valid from
        - Valid until
        - SubjectAlternativeName
        - SubjectKeyIdentifier
        - AuthorityKeyIdentifier
        - BasicConstraints
        """
        san_output = None
        ext_ski = None
        ext_aki = None
        ext_bc = None
        ext_crldp = None
        ext_noocsp = None
        ext_ocsp = None
        ext_ct = None

        certificate = x509.load_pem_x509_certificate(pem.encode(), default_backend())

        # Common Name (CN)
        subject = certificate.subject.rfc4514_string()
        self._logger.debug(subject)
        sdict = self.scan_subject(subject)
        # Some certificates do not have a CN set in subject. Use OU instead.
        cert_name = sdict.get("CN") if sdict.get("CN") is not None else sdict.get("OU")

        # Rest of subject line without CN
        subject_rest = ""
        for key in ('O', 'OU', 'C'):
            subject_rest += f"{key}={sdict[key]}," if sdict.get(key) else ""

        # Certificate issuer
        issuer = certificate.issuer.rfc4514_string()
        issuer_dict = self.scan_subject(issuer)

        issuer_rest = ""
        for key in ('O', 'OU', 'C'):
            issuer_rest += f"{key}={sdict[key]}," if sdict.get(key) else ""

        # Extension: SubjectAlternativeName
        try:
            ext_san = certificate.extensions.get_extension_for_oid(x509.OID_SUBJECT_ALTERNATIVE_NAME)
            san_output = ','.join(ext_san.value.get_values_for_type(x509.DNSName))
        except x509.extensions.ExtensionNotFound as e:
            self._logger.debug(f"SAN: {e}")

        # Extension: SubjectKeyIdentifier
        try:
            ext_ski = certificate.extensions.get_extension_for_oid(x509.OID_SUBJECT_KEY_IDENTIFIER)
        except x509.extensions.ExtensionNotFound as e:
            self._logger.debug(f"SubjectKeyIdentifier: {e}")

        # Extension: AuthorityKeyIdentifier
        try:
            ext_aki = certificate.extensions.get_extension_for_oid(x509.OID_AUTHORITY_KEY_IDENTIFIER)
        except x509.extensions.ExtensionNotFound as e:
            self._logger.debug(f"AuthorityKeyIdentifier: {e}")

        # Extension: BasicConstraints
        try:
            ext_bc = certificate.extensions.get_extension_for_oid(x509.OID_BASIC_CONSTRAINTS)
        except x509.extensions.ExtensionNotFound as e:
            self._logger.debug(f"BasicConstraints: {e}")

        # Extension: CRL Distribution Points
        try:
            ext_crldp = certificate.extensions.get_extension_for_oid(x509.OID_CRL_DISTRIBUTION_POINTS)
        except x509.extensions.ExtensionNotFound:
            pass

        # Extension: OCSP
        try:
            ext_noocsp = certificate.extensions.get_extension_for_oid(x509.OID_OCSP_NO_CHECK)
        except x509.extensions.ExtensionNotFound:
            pass

        try:
            ext_ocsp = certificate.extensions.get_extension_for_oid(x509.OID_AUTHORITY_INFORMATION_ACCESS)
        except x509.extensions.ExtensionNotFound:
            pass

        # Extension: Certificate Transparency
        try:
            ext_ct = certificate.extensions.get_extension_for_oid(x509.oid.ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS)
        except x509.extensions.ExtensionNotFound:
            pass

        # Output
        if not self._quiet:
            skip = False
            if self.filter_cn is not None:
                skip = True
                match = re.search(self.filter_cn, cert_name)
                if match:
                    skip = False
            if self.filter_ski:
                skip = True
                if ext_ski and self.filter_ski == ext_ski.value.digest.hex():
                    skip = False
            if self.filter_aki is not None:
                skip = True
                if ext_aki and self.filter_aki == ext_aki.value.key_identifier.hex():
                    skip = False

            if not skip:
                print(f'{linenr:>5}: {cert_name}')

                if self._verbose:
                    if subject_rest and len(subject_rest) > 0:
                        print(f"       Subject: {subject_rest[:-1]}")
                    print(f'       Issuer CN: {issuer_dict.get("CN")}')
                    if issuer_rest and len(issuer_rest) > 0:
                        print(f"       Issuer: {subject_rest[:-1]}")
                    print(f"       Not before: {certificate.not_valid_before}")
                    print(f"       Not after: {certificate.not_valid_after}")
                    if san_output and len(san_output) > 0:
                        print(f"       SubjectAlternativeName: {san_output}")
                    if ext_ski:
                        val = ext_ski.value.digest.hex()
                        print(f"       SubjectKeyIdentifier: {':'.join(val[s:s+2].upper() for s in range(0, len(val), 2))}")
                    if ext_aki:
                        val = ext_aki.value.key_identifier.hex()
                        print(f"       AuthorityKeyIdentifier: "
                              f"{':'.join(val[s:s+2].upper() for s in range(0, len(val), 2))}")
                    if ext_bc:
                        print(f"       BasicConstraints: CA={ext_bc.value.ca},Critical={ext_bc.critical}")
                    if ext_crldp:
                        for dp in ext_crldp.value:
                            for crl_uri in dp.full_name:
                                print(f"       CRL URI: {crl_uri.value}")
                    if ext_noocsp:
                        print(f"       No OCSP: {ext_noocsp.value}")
                    if ext_ocsp:
                        for access_description in ext_ocsp.value:
                            # Access descriptions can be for either OCSP or issuer. We are only going for OCSP.
                            if access_description.access_method == x509.oid.AuthorityInformationAccessOID.OCSP:
                                print(f"       OCSP URI: {access_description.access_location.value}")
                    if ext_ct:
                        sct: x509.certificate_transparency.SignedCertificateTimestamp = None
                        for sct in ext_ct.value:
                            print(f"       Certificate Transparency Log: {sct.log_id}")

        return certificate, cert_name

    def scan(self) -> None:
        pass


class FileCertStore(CertStore):
    """One or more certificates are stored in a single file"""
    def __init__(self, filename: str, quiet: bool = False, verbose: bool = False, debug: bool = False):
        super().__init__(quiet=quiet, verbose=verbose, debug=debug)
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
                                certificate, cert_name = self.scan_pem(pem, linenr=beginnr)
                                if certificate:
                                    # We found a valid certificate
                                    self.store_cert(certificate)
                                    ret = self.run_checks()
                                    if not ret:
                                        if not ret:
                                            self._logger.error(
                                                f"Failed checks for {cert_name} ({self.__filename})")
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


def find_cert(cert_stor_list: CertStore, name: str) -> x509.Certificate:
    """Find certificate by name"""
    for file_stor in cert_stor_list:
        for ski, cert in file_stor.cert_list.items():
            sdict = file_stor.scan_subject(cert.subject.rfc4514_string())
            cert_name = sdict.get("CN") if sdict.get("CN") is not None else sdict.get("OU")

            if cert_name == name:
                return cert

    return None


def check_chain(cert_stor_list: CertStore) -> bool:
    """
    Check that signing CA for every server certificate exists.
    Check that signing CA for every intermediate CA exists.

    :param cert_stor_list: List of certificate stores
    :return:
    """
    logger = logging.getLogger(__name__)
    logger.debug("CHECK INFO   : ...")

    ret = True

    for file_stor in cert_stor_list:
        for ski, cert in file_stor.cert_list.items():

            # Some certificates do not have a CN set in subject. Use OU instead.
            sdict = file_stor.scan_subject(cert.subject.rfc4514_string())
            cert_name = sdict.get("CN") if sdict.get("CN") is not None else sdict.get("OU")

            issuer_dict = file_stor.scan_subject(cert.issuer.rfc4514_string())
            issuer_name = issuer_dict.get("CN") if issuer_dict.get("CN") is not None else issuer_dict.get("OU")

            logger.debug(f"CHECK INFO   : Checking '{cert_name}' ({ski}) for issuer '{issuer_name}' ...")

            if file_stor.is_rootca(cert):
                logger.debug(f"CHECK INFO   : Skipping Root CA '{cert_name}'")
                continue

            try:
                ext_aki = cert.extensions.get_extension_for_oid(x509.OID_AUTHORITY_KEY_IDENTIFIER)
                aki = ext_aki.value.key_identifier.hex()
                if aki in file_stor.cert_list:
                    logger.debug(f"CHECK OK     : Found issuer '{issuer_name}'")
                else:
                    logger.error(f"Failed chain check for '{cert_name}'")
                    ret = False
            except x509.extensions.ExtensionNotFound:
                logger.debug(f"CHECK WARNING: Missing AuthorityKeyIdentifier for '{cert_name}'")
                ca_cert = find_cert(cert_stor_list, issuer_name)
                if ca_cert is not None:
                    logger.debug(f"CHECK OK     : Found issuer '{issuer_name}'")
                else:
                    logger.error(f"Failed chain check for '{cert_name}'")
                    ret = False

    return ret


def main():
    """Main program flow"""
    cert_store_list = []
    args = parseargs()
    get_logger(args.debug)
    ret = True

    # Scan a single file
    if os.path.isfile(args.filename):
        file_store = FileCertStore(args.filename, quiet=args.quiet, verbose=args.verbose, debug=args.debug)
        if args.expires is not None:
            file_store.enable_check(check_type=FileCertStore.CHECK_EXPIRES, check_param=args.expires)
        ret = file_store.scan()
        cert_store_list.append(file_store)

    # Scan a directory and all subdirectories
    if os.path.isdir(args.filename):
        for root, dir, files in os.walk(args.filename):
            for name in files:
                if re.match(r".*\.(pem|cert|crt|key)$", name, flags=re.IGNORECASE):
                    file_store = FileCertStore(os.path.join(root, name),
                                               quiet=args.quiet, verbose=args.verbose, debug=args.debug)
                    file_store.set_filter(cn=args.regex, ski=args.ski, aki=args.aki)
                    if args.expires is not None:
                        file_store.enable_check(check_type=FileCertStore.CHECK_EXPIRES, check_param=args.expires)
                    if not file_store.scan():
                        ret = False
                    cert_store_list.append(file_store)

        if args.chain is not None:
            if not check_chain(cert_store_list):
                ret = False

    exit(int(ret))


if __name__ == '__main__':
    main()
