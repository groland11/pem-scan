#!/usr/bin/env python3
import unittest
import importlib
pemscan = importlib.import_module("pem-scan")


class TestCert(unittest.TestCase):
    filename = "tests/www-google-com.pem"
    def test_cert(self):
        file_store = pemscan.FileCertStore(self.filename, quiet=True, verbose=False, debug=False)
        #file_store.enable_check(check_type=FileCertStore.CHECK_EXPIRES, check_param=args.expires)
        ret = file_store.scan()


if __name__ == '__main__':
    unittest.main()