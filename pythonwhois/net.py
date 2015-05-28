import socket
import sys

import re
from codecs import encode, decode
from . import shared


class WhoisParser(object):

    IANA_SERVER = "whois.iana.org"

    whois_regexp = re.compile(
        r"(?:refer|whois server|referral url|whois server|registrar whois)"
        r":\s*([^\s]+\.[^\s]+)", re.IGNORECASE)

    root_servers = {
        ".ac.uk": "whois.ja.net",
        ".ps": "whois.pnina.ps",
        ".buzz": "whois.nic.buzz",
        ".moe": "whois.nic.moe",
        # The following is a bit hacky, but IANA won't return the right
        # answer for example.com because it's a direct registration.
        "example.com": "whois.verisign-grs.com"
    }

    def __init__(self, domain, rfc3490=True):
        self._domain = domain
        self.rfc3490 = rfc3490

    @property
    def domain(self):
        return self._domain

    @property
    def domain_rfc3490(self):
        converted_key = '_domain_rfc3490'
        converted = getattr(self, converted_key, None)
        if converted is None:
            converted = self.convert_to_rfc3490(self.domain)
            setattr(self, converted_key, converted)
        return converted

    @classmethod
    def convert_to_rfc3490(cls, domain):
        if sys.version_info < (3, 0):
            domain = encode(domain if type(domain) is unicode
                            else decode(domain, "utf8"), "idna")
        else:
            domain = encode(domain, "idna").decode("ascii")
        return domain

    @classmethod
    def get_default_server(cls, domain):
        for pattern, server in cls.root_servers.items():
            if domain.endswith(pattern):
                return server

    @classmethod
    def prepare_request(cls, domain, server):
        if server == "whois.jprs.jp":
            request = "%s/e" % domain  # Suppress Japanese output
        elif (domain.endswith(".de")
              and (server == "whois.denic.de"
                   or server == "de.whois-servers.net")):
            request = "-T dn,ace %s" % domain  # regional specific stuff
        elif server == "whois.verisign-grs.com":
            request = "=%s" % domain  # Avoid partial matches
        else:
            request = domain
        return request

    @classmethod
    def extract_whois_server(cls, response, server_list=None):
        server_list = server_list or []
        items = cls.whois_regexp.findall(response)
        for item in items:
            server = item.strip()
            if server not in server_list and "://" not in server:
                return server

    def _server_request(self, request, server, port=43):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((server, port))
        sock.send(("%s\r\n" % request).encode("utf-8"))
        buff = b""
        while True:
            data = sock.recv(1024)
            if len(data) == 0:
                break
            buff += data
        return buff

    def _server_process_result(self, result, server):
        encodings = ("utf-8", "iso-8859-1")
        for encoding in encodings:
            try:
                return result.decode(encoding)
            except ValueError:
                pass
        raise ValueError(("Could not decode whois response "
                          "from {server}").format(server=server))

    def _process_response(self, response, domain, server,
                          previous, server_list, never_cut=False):
        if never_cut:
            # If the caller has requested to 'never cut' responses, he will get
            # the original response from the server (this is useful for callers
            # that are only interested in the raw data). Otherwise, if the target
            # is verisign-grs, we will select the data relevant to the requested
            # domain, and discard the rest, so that in a multiple-option response
            # the parsing code will only touch the information relevant to the
            # requested domain. The side-effect of this is that when `never_cut`
            # is set to False, any verisign-grs responses in the raw data will be
            # missing header, footer, and alternative domain options (this is
            # handled a few lines below, after the verisign-grs processing).
            previous.insert(0, response)
        if server == "whois.verisign-grs.com":
            # VeriSign is a little... special. As it may return multiple
            # full records and there's no way to do an exact query,
            # we need to actually find the correct record in the list.
            for record in response.split("\n\n"):
                if re.search("Domain Name: %s\n" % domain.upper(), record):
                    response = record
                    break
        if not never_cut:
            previous.insert(0, response)
        server_list.append(server)
        return response

    def get_root_server(self):
        default_server = self.get_default_server(self.domain)
        if default_server is not None:
            return default_server

        domain = self.domain_rfc3490 if self.rfc3490 else self.domain
        data = self.whois_request(domain, self.IANA_SERVER)
        new_server = self.extract_whois_server(data)
        if new_server is None:
            raise shared.WhoisException(
                "No root WHOIS server found for domain.")
        return new_server

    def whois_request(self, request, server, port=43):
        result = self._server_request(request, server, port)
        return self._server_process_result(result, server)

    def get_whois_raw(self, server=None, previous=None, never_cut=False,
                      with_server_list=False, server_list=None):

        previous = previous or []
        server_list = server_list or []

        whois_server = server or self.get_root_server()
        domain = self.domain_rfc3490 if self.rfc3490 else self.domain
        request = self.prepare_request(domain, whois_server)
        response = self.whois_request(request, whois_server)
        response = self._process_response(
            response, domain, whois_server,
            previous, server_list, never_cut)

        new_server = self.extract_whois_server(response, server_list)
        if new_server is not None:
            return self.get_whois_raw(new_server, previous, never_cut,
                                      with_server_list, server_list)

        if with_server_list:
            return previous, server_list
        else:
            return previous


def get_whois_raw(domain, server="", rfc3490=True, never_cut=False):
    parser = WhoisParser(domain, rfc3490=rfc3490)
    return parser.get_whois_raw(server=server, never_cut=never_cut)


def get_root_server(domain):
    return WhoisParser(domain).get_root_server()
