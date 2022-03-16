#!/usr/bin/env python3
# *******************************************************************
#   A monitoring tool for certificate transparency.
# *******************************************************************

# Modules
import calendar
import json
import requests
import time
try:
    from urllib.parse import quote_plus
except ImportError:
    from urllib import quote_plus


def notification_handler(notification_message):
    """
    This function should be customized based off the user needs
    for notification channel.
    """

    print(notification_message)
    return(0)


def notify(ctr_hash=None,
           domain=None,
           cert_data=None,
           zero_results=False,
           scan_finished=False):
    """
    This function notifies users about results of scans,
    and when a scan finishes.
    Edit the TEMPLATE variable to customize notification messages.
    """

    if zero_results is True:
        # Message informing that there is no certificates identified.
        TEMPLATE = "No new certificates were identified for %s." % (domain)
#    elif scan_finished is True:
#        # Message informing that a scan is finished for a domain.
#        TEMPLATE = "Scan finished for %s." % (domain)
    else:
        current_date = calendar.timegm(time.gmtime())
        # Message informing a user with new identified certificate.
        TEMPLATE = """The following certificate has been identified:
* CTR_Hash: %s
* Domain: %s
* Date Discovered: %s
* dnsNames: %s
* validFrom: %s
* validTo: %s
* serialNumber: %s
* subject: %s
* signatureAlgorithm: %s
* issuer: %s
    """ % (ctr_hash,
           domain,
           format_date(current_date),
           cert_data["dnsNames"],
           format_date(cert_data["validFrom"], certificate_date=True),
           format_date(cert_data["validTo"], certificate_date=True),
           cert_data["serialNumber"],
           cert_data["subject"],
           cert_data["signatureAlgorithm"],
           cert_data["issuer"])

    notification_handler(TEMPLATE)
    return(0)


def format_date(epoch, certificate_date=False):
    if certificate_date:
        return time.strftime('%d-%B-%Y %H:%M:%S UTC', time.gmtime((int(epoch / 1000))))
    else:
        return time.strftime('%d-%B-%Y %H:%M:%S UTC', time.gmtime(epoch))


class GoogleCTR_API(object):
    def __init__(self):
        """
        self.timeout: The request's timeout.
        self.user_agent: The request's HTTP User-Agent.
        self.headers: The requests HTTP headers.
        """

        self.timeout = 4
        self.user_agent = "ct-monitor (https://github.com/ProtonMail/ct-monitor)"
        self.headers = {"User-Agent": self.user_agent, 'Accept': '*/*'}

    def certificates_of_domain_query_parser(self, response):
        """
        Parses the first step response, and returns the output as dict.
        Input:
        response: the response of the request.
        Output:
        output: A dict:
        hashes: A list of CTR hashes.
        nextPageToken: The token of next page.
        """

        output = {"hashes": [], "nextPageToken": ""}
        if response[0][0] == str("er"):
            output["nextPageToken"] = None
            return(output)

        try:
            output["nextPageToken"] = str(response[0][-1][1])
        except KeyError:
            output["nextPageToken"] = None  # Reached last page.

        for i in range(len(response[0][1])):
            ctr_hash = response[0][1][i][5]
            output["hashes"].append(ctr_hash)

        return(output)

    def get_certificates_of_domain(self, domain):
        """
        Gets a list of CTR hashes associated with the domain.
        Input:
        domain: the domain to scan.
        Output:
        a list of CTR hashes associated with the domain.
        """

        output = []
        token = ""

        while token is not None:

            if token == "":
                url = "https://transparencyreport.google.com/transparencyreport/api/v3/httpsreport/ct/certsearch?include_expired=true&include_subdomains=false&domain={0}".format(quote_plus(domain))
            else:
                url = "https://transparencyreport.google.com/transparencyreport/api/v3/httpsreport/ct/certsearch/page?include_expired=true&include_subdomains=false&domain={0}&p={1}".format(quote_plus(domain), quote_plus(token))
            print("Retrieving", url)
            resp = requests.get(url, headers=self.headers, timeout=self.timeout)

            if resp.status_code == 503:
                return(output)

            resp = json.loads(resp.text.split("\n\n")[1])

            if (resp[0][1] is not None) and (len(resp[0][1]) == 0):
                return(output)

            parsed_response = self.certificates_of_domain_query_parser(resp)

            token = parsed_response["nextPageToken"]
            output.extend(parsed_response["hashes"])
        return(output)

    def get_certificate_details(self, ctr_hash):
        """
        Returns certificate details of a certificate.
        Input:
        ctr_hash: CTR Hash for the certificate.
        Output:
        a dict that holds:
        dnsNames: dnsNames entry.
        validFrom: validFrom entry.
        validTo: validTo entry.
        serialNumber: serialNumber entry.
        subject: subject entry.
        signatureAlgorithm: signatureAlgorithm entry.
        issuer: issuer entry.
        """

        output = {}
        url = "https://transparencyreport.google.com/transparencyreport/api/v3/httpsreport/ct/certbyhash?hash={0}".format(quote_plus(ctr_hash))
        resp = requests.get(url, headers=self.headers, timeout=self.timeout)
        if resp.status_code == 503:
            output = {"dnsNames": "NA",
                      "validFrom": "NA",
                      "validTo": "NA",
                      "serialNumber": "NA",
                      "subject": "NA",
                      "signatureAlgorithm": "NA",
                      "certificateType": "NA",
                      "issuer": "NA"}
            return(output)
        resp = json.loads(resp.text.split("\n\n")[1])

        output.update({"serialNumber": resp[0][1][0]})
        output.update({"subject": resp[0][1][1]})
        output.update({"issuer": resp[0][1][2]})
        output.update({"validFrom": resp[0][1][3]})
        output.update({"validTo": resp[0][1][4]})
        output.update({"signatureAlgorithm": resp[0][1][6]})
        if resp[0][1][7] == "":
            output.update({"dnsNames": "NA"})
        else:
            output.update({"dnsNames": ", ".join(resp[0][1][7])})

        return(output)


