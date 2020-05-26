from six.moves.urllib.parse import urlparse, urljoin

import logging
import xml.etree.ElementTree as ET

import requests
from requests_kerberos import HTTPKerberosAuth, OPTIONAL

try:  # Python 2.7+
    from logging import NullHandler
except ImportError:
    # Hello, you are using a 10 year old software. :(
    class NullHandler(logging.Handler):
        def emit(self, record):
            pass


log = logging.getLogger(__name__)
log.addHandler(NullHandler())

DEFAULT_TIMEOUT_SECONDS = 10



# ____________________________________________________
# Context manager to temporarily disable ssl verification
# see: https://stackoverflow.com/a/15445989/9209944

import warnings
import contextlib
from urllib3.exceptions import InsecureRequestWarning

old_merge_environment_settings = requests.Session.merge_environment_settings

@contextlib.contextmanager
def no_ssl_verification():
    opened_adapters = set()

    def merge_environment_settings(self, url, proxies, stream, verify, cert):
        # Verification happens only once per connection so we need to close
        # all the opened adapters once we're done. Otherwise, the effects of
        # verify=False persist beyond the end of this context manager.
        opened_adapters.add(self.get_adapter(url))

        settings = old_merge_environment_settings(self, url, proxies, stream, verify, cert)
        settings['verify'] = False

        return settings

    requests.Session.merge_environment_settings = merge_environment_settings

    try:
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', InsecureRequestWarning)
            yield
    finally:
        requests.Session.merge_environment_settings = old_merge_environment_settings

        for adapter in opened_adapters:
            try:
                adapter.close()
            except:
                pass

# ____________________________________________________


def _init_session(s, url, cookiejar, auth_url_fragment):
    """
    Internal helper function: initialise the sesion by trying to access
    a given URL, setting up cookies etc.


    :param: auth_url_fragment: a URL fragment which will be joined to
    the base URL after the redirect, before the parameters. Examples are
    auth/integrated/ (kerberos) and auth/sslclient/ (SSL)
    """

    if cookiejar is not None:
        log.debug("Using provided cookiejar")
        s.cookies = cookiejar

    # Try getting the URL we really want, and get redirected to SSO
    log.info("Fetching URL: %s" % url)
    r1 = s.get(url, timeout=DEFAULT_TIMEOUT_SECONDS)

    # Parse out the session keys from the GET arguments:
    redirect_url = urlparse(r1.url)
    log.debug("Was redirected to SSO URL: %s" % str(redirect_url))

    # ...and inject them into the Kerberos authentication URL
    final_auth_url = "{auth_url}?{parameters}".format(
        auth_url=urljoin(r1.url, auth_url_fragment),
        parameters=redirect_url.query)

    return final_auth_url


def _finalise_login(s, auth_results, return_session=False):
    """
    Perform the final POST authentication steps to fully authenticate
    the session, saving any cookies in s' cookie jar.
    """

    r2 = auth_results

    # Did it work? Raise Exception otherwise.
    r2.raise_for_status()

    # Get the contents
    try:
        tree = ET.fromstring(r2.content)
    except ET.ParseError as e:
        log.error("Could not parse response from server!")
        log.error("The contents returned was:\n{}".format(r2.content))
        raise e

    action = tree.findall("body/form")[0].get('action')

    # Unpack the hidden form data fields
    form_data = dict((
        (elm.get('name'), elm.get('value'))
        for elm in tree.findall("body/form/input")))

    # ...and submit the form (WHY IS THIS STEP EVEN HERE!?)
    log.debug("Performing final authentication POST to %s" % action)
    r3 = s.post(url=action, data=form_data, timeout=DEFAULT_TIMEOUT_SECONDS)

    # Did _that_ work?
    r3.raise_for_status()

    # The session cookie jar should now contain the necessary cookies.
    log.debug("Cookie jar now contains: %s" % str(s.cookies))

    return s if return_session else s.cookies


def krb_sign_on(url, cookiejar=None, return_session=False):
    """
    Perform Kerberos-backed single-sign on against a provided
    (protected) URL.

    It is assumed that the current session has a working Kerberos
    ticket.

    Returns a Requests `CookieJar`, which can be accessed as a
    dictionary, but most importantly passed directly into a request or
    session via the `cookies` keyword argument.

    If a cookiejar-like object (such as a dictionary) is passed as the
    cookiejar keword argument, this is passed on to the Session.
    """

    kerberos_auth = HTTPKerberosAuth(mutual_authentication=OPTIONAL)

    with requests.Session() as s:

        krb_auth_url = _init_session(s=s, url=url, cookiejar=cookiejar,
                                     auth_url_fragment=u"auth/integrated/")

        # Perform actual Kerberos authentication
        log.info("Performing Kerberos authentication against %s"
                 % krb_auth_url)

        r2 = s.get(krb_auth_url, auth=kerberos_auth,
                   timeout=DEFAULT_TIMEOUT_SECONDS)

        return _finalise_login(s, auth_results=r2, return_session=return_session)

def krb_sign_on_noverify(url, cookiejar=None, return_session=False):
    """
    Wrapper around krb_sign_on that disables ssl verification
    Many cern.ch endpoints require the cern root certificate and editing
    all this code to be able to handle certificates is a pain, hence turning
    ssl verification off entirely.

    Clearly this is suboptimal and the user should be careful
    """
    log.warning('Turning off ssl verification entirely - please be careful')
    with no_ssl_verification():
        s = krb_sign_on(url, cookiejar, return_session=return_session)
    if return_session: s.verify = False
    return s

def cert_sign_on(url, cert_file, key_file, cookiejar={}):
    """
    Perform Single-Sign On with a robot/user certificate specified by
    cert_file and key_file agains the target url. Note that the key
    needs to be passwordless. cookiejar, if provided, will be used to
    store cookies, and can be a Requests CookieJar, or a
    MozillaCookieJar. Or even a dict.

    Cookies will be returned on completion, but cookiejar will also be
    modified in-place.

    If you have a PKCS12 (.p12) file, you need to convert it. These
    steps will not work for passwordless keys.

    `openssl pkcs12 -clcerts -nokeys -in myCert.p12 -out ~/private/myCert.pem`

    `openssl pkcs12 -nocerts -in myCert.p12 -out ~/private/myCert.tmp.key`

    `openssl rsa -in ~/private/myCert.tmp.key -out ~/private/myCert.key`

    Note that the resulting key file is *unencrypted*!

    """

    with requests.Session() as s:

        # Set up the certificates (this needs to be done _before_ any
        # connection is opened!)
        s.cert = (cert_file, key_file)

        cert_auth_url = _init_session(s=s, url=url, cookiejar=cookiejar,
                                      auth_url_fragment=u"auth/sslclient/")

        log.info("Performing SSL Cert authentication against %s"
                 % cert_auth_url)

        r2 = s.get(cert_auth_url, cookies=cookiejar, verify=False,
                   timeout=DEFAULT_TIMEOUT_SECONDS)

        return _finalise_login(s, auth_results=r2)
