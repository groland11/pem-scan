#!/usr/bin/env python3
# Requires package python3-dnspython

import argparse
import configparser
import csv
from datetime import datetime, timedelta
import dns.resolver
import logging
import OpenSSL
import os
import re
import sys
import urllib.request
import google_ctr

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
    parser.add_argument("--crl", action="store_true",
                        help="check Certificate Revocation List (CRL)")
    parser.add_argument("--caa", action="store_true",
                        help="check CAA record in DNS")
    parser.add_argument("--ctr", action="store_true",
                        help="check Certificate Transparency Record (CTR)")
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
    CHECK_CRL = 2

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
        """Return True if any filter has been set"""
        if self.filter_cn is not None or \
                self.filter_ski is not None or \
                self.filter_aki is not None:
            return True
        else:
            return False

    def get_subject(self) -> str:
        """Return subject of current certificate"""
        if self._current_cert == None:
            return ""

        subject_dict = self.scan_subject(self._current_cert.subject.rfc4514_string())
        # Some certificates do not have a CN set in subject. Use OU instead.
        subject_name = subject_dict.get("CN") if subject_dict.get("CN") is not None else subject_dict.get("OU")
        return subject_name

    def get_serialnumber(self) -> str:
        """Return serialnumber of current certificate"""
        if self._current_cert == None:
            return ""

        serialstring = ""
        serialnumber = "{0:x}".format(self._current_cert.serial_number)
        for i in range(0, len(serialnumber), 2):
            serialstring += serialnumber[i:i+2] + ":"

        return serialstring[:-1]

    def get_hostnames(self) -> set:
        """Return list of hostnames / domains for which certificate has been signed"""
        hostnames = set()

        if self._current_cert == None:
            return hostnames

        # Get CN
        subject = self._current_cert.subject.rfc4514_string()
        cn = self.scan_subject(subject).get("CN")
        if cn is None:
            return hostnames
        else:
            hostnames.add(cn)

        # Get additional hostnames from X509v3 Subject Alternative Name extension
        try:
            ext_san = self._current_cert.extensions.get_extension_for_oid(x509.OID_SUBJECT_ALTERNATIVE_NAME)
            hostnames.update(ext_san.value.get_values_for_type(x509.DNSName))
        except x509.extensions.ExtensionNotFound as e:
            pass

        return hostnames

    def get_issuer(self) -> str:
        """Return issuer of current certificate"""
        if self._current_cert == None:
            return ""

        issuer_dict = self.scan_subject(self._current_cert.issuer.rfc4514_string())
        # Some certificates do not have a CN set in subject. Use OU instead.
        issuer_name = issuer_dict.get("CN") if issuer_dict.get("CN") is not None else issuer_dict.get("OU")
        return issuer_name

    def get_organisation(self) -> str:
        """Return issuer organisation of current certificate"""
        if self._current_cert == None:
            return ""

        issuer_dict = self.scan_subject(self._current_cert.issuer.rfc4514_string())
        # Some certificates do not have a CN set in subject. Use OU instead.
        issuer_organisation = issuer_dict.get("O") if issuer_dict.get("O") is not None else issuer_dict.get("OU")
        return issuer_organisation

    def is_ca(self) -> bool:
        """
        Check if certificate is CA:
        - Only check for Basic Constraint Extension

        :return: True - Certificate is a CA certificate
        """
        # Gracefully handle error conditions
        if self._current_cert is None:
            return False

        # Check BasicConstraint
        try:
            ext_bc = self._current_cert.extensions.get_extension_for_oid(x509.OID_BASIC_CONSTRAINTS)
            if ext_bc.value.ca == True:
                return True
        except x509.extensions.ExtensionNotFound:
            # Assume that Root CAs must have Basic Constraint set
            return False

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

        # Check if subject and issuer are identical
        subject_name = self.get_subject()
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

    def check_crl(self, param=None) -> bool:
        """
        Check certificate revocation lists
        Errors will be written to stdout
        """
        try:
            ext_crldp = self._current_cert.extensions.get_extension_for_oid(x509.OID_CRL_DISTRIBUTION_POINTS)
        except x509.extensions.ExtensionNotFound:
            return True

        for dp in ext_crldp.value:
            for crl_uri in dp.full_name:
                try:
                    crl_filename, headers = urllib.request.urlretrieve(crl_uri.value)
                except  urllib.error.HTTPError as e:
                    self._logger.warning(f"CRL: Error loading CRL from {crl_uri.value} ({e})")
                    return False

                with open(crl_filename, 'r') as crl_file:
                    crl = "".join(crl_file.readlines())

                crl_object = OpenSSL.crypto.load_crl(OpenSSL.crypto.FILETYPE_PEM, crl)
                revoked_objects = crl_object.get_revoked()
                for rvk in revoked_objects:
                    self._logger.debug(f"       Revoked Serial: {rvk.get_serial()}")
                    if rvk.get_serial() == self._current_cert.serial_number:
                        self._logger.error(
                            f"{Fore.LIGHTWHITE_EX}{Back.RED}FAIL{Style.RESET_ALL}: \
                            Certificate has been revoked (Serial={rvk.get_serial()})")
                        return False

        return True

    def validate_caa(self, issuer_domain: str, issuer_cn: str, issuer_o: str) -> bool:
        """
        Check if issuer_domain as given in CAA record matches CN in issuer field of certificate
        Reads CSV file 'IncludedCACertificateReport.csv' in current directory
        (s. https://wiki.mozilla.org/CA/Included_Certificates)

        :param issuer_domain:
        :param issuer_cn:
        :return:
        """
        filename = os.path.join(os.path.dirname(os.path.realpath(__file__)), "IncludedCACertificateReport.csv")

        if issuer_domain == ";" or issuer_domain == "":
            self._logger.debug(f"CHECK INFO   : Invalid issuer domain {issuer_domain}")
            return False

        try:
            with open(filename, "r") as file:
                reader = csv.DictReader(file)
                for row in reader:
                    domain = ""

                    match = re.match(r"https?://([^/]+)", row.get('Company Website'))
                    if match:
                        domain = match.group(1)
                        while len(domain.split('.')) > 2:
                            domain = domain.split('.', maxsplit=1)[1]

                    if issuer_domain == domain:
                        if issuer_cn == row.get('Common Name or Certificate Name'):
                            return True
                        else:
                            self._logger.debug(
                                f"CHECK INFO   : CAA - {row.get('Common Name or Certificate Name')} not matching "
                                f"certificate CN {issuer_cn}")
                        if row.get('Certificate Issuer Organization').startswith(issuer_o):
                            return True
                        else:
                            self._logger.debug(
                                f"CHECK INFO   : CAA - '{row.get('Certificate Issuer Organization')}' not matching "
                                f"certificate organization '{issuer_o}'")
        except FileNotFoundError:
            self._logger.error(f"Missing CSV file {filename} with list of valid CAs (s. https://wiki.mozilla.org/CA/Included_Certificates)")

        self._logger.error(f"{Fore.LIGHTWHITE_EX}{Back.RED}FAIL{Style.RESET_ALL}: Issuer '{issuer_cn}' not matching CAA info")
        return False

    def enable_check(self, check_type: int, check_param: object=None) -> None:
        """
        Enabble individual checks on certificate data
        Checks to be performed are all stored in a dictionary
        """
        if check_type == CertStore.CHECK_EXPIRES:
            self._check_list[self.check_expires] = check_param
        if check_type == CertStore.CHECK_CAA:
            self._check_list[self.check_caa] = None
        if check_type == CertStore.CHECK_CRL:
            self._check_list[self.check_crl] = None

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
        subject_dict = self.scan_subject(subject)
        # Some certificates do not have a CN set in subject. Use OU instead.
        cert_name = subject_dict.get("CN") if subject_dict.get("CN") is not None else subject_dict.get("OU")

        # Rest of subject line without CN
        subject_rest = ""
        for key in ('O', 'OU', 'C'):
            subject_rest += f"{key}={subject_dict[key]}," if subject_dict.get(key) else ""

        # Certificate issuer
        issuer = certificate.issuer.rfc4514_string()
        issuer_dict = self.scan_subject(issuer)

        issuer_rest = ""
        for key in ('O', 'OU', 'C'):
            issuer_rest += f"{key}={issuer_dict[key]}," if issuer_dict.get(key) else ""

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
                        print(f"       Issuer: {issuer_rest[:-1]}")
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


def find_cert(cert_stor_list: list, name: str) -> x509.Certificate:
    """Find certificate by name"""
    for file_stor in cert_stor_list:
        for ski, cert in file_stor.cert_list.items():
            sdict = file_stor.scan_subject(cert.subject.rfc4514_string())
            cert_name = sdict.get("CN") if sdict.get("CN") is not None else sdict.get("OU")

            if cert_name == name:
                return cert

    return None


def check_chain(cert_stor_list: list) -> bool:
    """
    Check that signing CA for every server certificate exists.
    Check that signing CA for every intermediate CA exists.

    :param cert_stor_list: List of certificate stores
    :return: True - Check passed
    """
    logger = logging.getLogger(__name__)
    logger.debug("CHECK INFO   : check_chain")

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


def check_caa(cert_stor_list: list) -> bool:
    """
    Check if CAA record in DNS conforms to issuer attribute in certificate
    Valid CAs are taken from https://wiki.mozilla.org/CA/Included_Certificates
    Errors will be written to stdout

    :param cert_stor_list: List of certificate stores
    :return: True - Check passed
    """
    # TODO: First find root CA, then check root CA against CAA info
    issuers = []
    ret = True
    logger = logging.getLogger(__name__)

    for file_stor in cert_stor_list:
        hostnames = file_stor.get_hostnames()
        subject = file_stor.get_subject()

        # Do not check CA certificates
        if file_stor.is_ca():
            continue

        logger.debug(f"CHECK INFO   : check_caa for cert '{subject}'")

        # There can be multiple hostnames/domains in a certificate
        for hostname in hostnames:
            logger.debug(f"CHECK INFO   : check_caa for hostname '{hostname}'")
            hostname_ok = False

            # Lookup CAA record for hostname itself and all parent domains
            while(len(hostname.split('.')) >= 2):
                try:
                    result = dns.resolver.query(hostname, 'CAA', raise_on_no_answer=False)
                except dns.resolver.NXDOMAIN as e:
                    break

                if len(result.response.answer) == 0:
                    # If we didn't receive a caa record, try parent domain
                    try:
                        hostname = hostname.split('.', 1)[1]
                    except IndexError:
                        pass
                else:
                    # There can be more than one CAA record for a hostname / domain
                    for answer in result.response.answer:
                        for record in answer:
                            match = re.match(r"\d+ issue (.*)", record.to_text())
                            if match:
                                issuers.append(match.group(1).replace('"', ''))

                    # No valid issuers in CAA record found
                    if len(issuers) == 0:
                        try:
                            hostname = hostname.split('.', 1)[1]
                        except IndexError:
                            pass
                        continue

                    for issuer in issuers:
                        logger.debug(f"CHECK INFO   : CAA check for {issuer} ...")
                        if file_stor.validate_caa(issuer, file_stor.get_issuer(), file_stor.get_organisation()):
                            logger.debug(f"CHECK INFO   : Sucessfully checked CAA for hostname '{hostname}'")
                            hostname_ok = True
                            hostname = ""
                            break

            if not hostname_ok:
                # If one hostname check fails, the whole caa check fails
                ret = False

    # If there is no CAA info, check will pass ok
    return ret


def check_ctr(cert_stor_list: list) -> bool:
    """
    Check certificate transparency report (CTR)
    Errors will be written to stdout

    :param cert_stor_list: List of certificate stores
    :return: True - Check passed
    """
    ret = True
    logger = logging.getLogger(__name__)

    for file_stor in cert_stor_list:
        issuer = file_stor.get_issuer()
        subject = file_stor.get_subject()
        hostnames = file_stor.get_hostnames()
        serialnumber = file_stor.get_serialnumber()

        # Do not check CA certificates
        if file_stor.is_ca():
            continue

        for hostname in hostnames:
            logger.debug(f"CHECK INFO   : check_ctr for cert '{subject}', hostname '{hostname}'")
            hostname_ok = False

            ctr_hashes = google_ctr.GoogleCTR_API().get_certificates_of_domain(hostname)
            logger.debug(f"CHECK INFO   : Retrieved {len(ctr_hashes)} certificate transparency log entries for hostname '{hostname}'")
            for ctr_hash in ctr_hashes:
                cert_data = google_ctr.GoogleCTR_API().get_certificate_details(ctr_hash)
                ct_serialnumber = cert_data.get('serialNumber')
                if ct_serialnumber is not None and ct_serialnumber.lower() == serialnumber:
                    logger.debug(f"CHECK INFO   : Found serial {serialnumber} in CT log")
                    try:
                        match = re.search(f"CN={issuer}", cert_data.get('issuer'))
                    except:
                        pass
                    else:
                        if match:
                            logger.debug(f"CHECK INFO   : Found issuer '{issuer}' in CT log")
                            hostname_ok = True
                            break
                else:
                    logger.debug(f"CHECK INFO   : serial = '{ct_serialnumber}'")

            if not hostname_ok:
                # If one hostname check fails, the whole ctr check fails
                ret = False

    return ret


def get_config() -> set:
    """
    Read configuration file

    :return: Dictionary of configuration values
    """
    logger = logging.getLogger(__name__)
    filenames = [os.getcwd() + "/pem-scan.ini", "/etc/pem-scan.ini"]
    files = []
    ret = {}

    cp = configparser.ConfigParser()
    for filename in filenames:
        try:
            files = cp.read(filename)
            break
        except Exception as e:
            logger.debug(f"Unable to open config file '{filename}' ({e})'")
            pass

    if len(files) == 0:
        return (None, [])

    for key in cp['release']:
        ret[key] = cp['release'][key]
        if key == "exclude":
            excludes = ret[key].split(",")

    return (ret, excludes)


def main():
    """Main program flow"""
    cert_store_list = []
    args = parseargs()
    logger = get_logger(args.debug)
    config, excludes = get_config()
    file_store = None
    ret = 0

    # Scan a single file
    if os.path.isfile(args.filename):
        file_store = FileCertStore(args.filename, quiet=args.quiet, verbose=args.verbose, debug=args.debug)
        if args.expires is not None:
            file_store.enable_check(check_type=FileCertStore.CHECK_EXPIRES, check_param=args.expires)
        if args.crl:
            file_store.enable_check(check_type=FileCertStore.CHECK_CRL)
        if not file_store.scan():
            ret += 1
        cert_store_list.append(file_store)
    # Scan a directory and all subdirectories
    elif os.path.isdir(args.filename):
        for root, dir, files in os.walk(args.filename):
            for name in files:
                skip = False

                # Check if directory is excluded in configuration file
                filename = os.path.join(root, name)
                for exclude in excludes:
                    if re.match(exclude, filename):
                        skip = True
                        logger.debug(f"Skipping excluded file '{filename}'")
                        break
                if skip: continue

                if re.match(r".*\.(pem|cert|crt|key)$", name, flags=re.IGNORECASE):
                    file_store = FileCertStore(filename, quiet=args.quiet, verbose=args.verbose, debug=args.debug)
                    file_store.set_filter(cn=args.regex, ski=args.ski, aki=args.aki)
                    if args.expires is not None:
                        file_store.enable_check(check_type=FileCertStore.CHECK_EXPIRES, check_param=args.expires)
                    if args.crl:
                        file_store.enable_check(check_type=FileCertStore.CHECK_CRL)
                    if not file_store.scan():
                        ret += 1
                    cert_store_list.append(file_store)

                    # Check of certificate chain only if checking directory trees
                    if args.chain == True:
                        if not check_chain(cert_store_list):
                            ret += 1
    else:
        # Invalid file/directory command line argument
        logger.error(f"Invalid file/directory argument '{args.filename}'")
        ret = 1

    # All remaining checks
    if file_store is not None:
        if args.caa:
            if not check_caa(cert_store_list):
                ret += 1
        if args.ctr:
            if not check_ctr(cert_store_list):
                ret += 1

    exit(ret)


if __name__ == '__main__':
    main()
