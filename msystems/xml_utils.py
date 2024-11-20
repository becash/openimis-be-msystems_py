import re
import datetime as py_datetime

from zeep.wsse.signature import _make_sign_key, _sign_envelope_with_key, _make_verify_key, _verify_envelope_with_key
from lxml import etree

from core import datetime
from msystems.apps import MsystemsConfig

ns_envelope = "http://schemas.xmlsoap.org/soap/envelope/"
ns_wss_util = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
ns_wss_s = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"

created_xpath = f"./{{{ns_envelope}}}Header/{{{ns_wss_s}}}Security/{{{ns_wss_util}}}Timestamp/{{{ns_wss_util}}}Created"
expires_xpath = f"./{{{ns_envelope}}}Header/{{{ns_wss_s}}}Security/{{{ns_wss_util}}}Timestamp/{{{ns_wss_util}}}Expires"


def add_signature(root, key, cert):
    key = _make_sign_key(key, cert, None)
    return _sign_envelope_with_key(root, key, None, None)


def verify_signature(root, cert):
    if not MsystemsConfig.verify_incoming_soap_messages:
        return

    key = _make_verify_key(cert)
    return _verify_envelope_with_key(root, key)


def add_timestamp(root):
    dt_now = datetime.datetime.from_ad_datetime(py_datetime.datetime.now(tz=py_datetime.timezone.utc))
    dt_expires = dt_now + datetime.datetimedelta(minutes=5)

    header = etree.SubElement(root, etree.QName(ns_envelope, "Header"))
    security = etree.SubElement(header, etree.QName(ns_wss_s, "Security"))
    timestamp = etree.SubElement(security, etree.QName(ns_wss_util, "Timestamp"))
    created = etree.SubElement(timestamp, etree.QName(ns_wss_util, "Created"))
    created.text = dt_now.strftime("%Y-%m-%dT%H:%M:%SZ")
    expires = etree.SubElement(timestamp, etree.QName(ns_wss_util, "Expires"))
    expires.text = dt_expires.strftime("%Y-%m-%dT%H:%M:%SZ")


def replace_utc_timezone_with_offset(dt_str):
    # Python 3.9 does not support Z timezone in datetime strings
    return re.sub(r'Z$', '+00:00', dt_str)


def verify_timestamp(root):
    if not MsystemsConfig.verify_incoming_soap_messages:
        return

    dt_now = datetime.datetime.from_ad_datetime(py_datetime.datetime.now(tz=py_datetime.timezone.utc))
    created, expires = root.find(created_xpath), root.find(expires_xpath)

    if created is None:
        raise ValueError('Created timestamp not found')
    dt_created = datetime.datetime.fromisoformat(replace_utc_timezone_with_offset(created.text))

    if expires is None:
        raise ValueError('Expires timestamp not found')
    dt_expires = datetime.datetime.fromisoformat(replace_utc_timezone_with_offset(expires.text))

    if dt_created > dt_now:
        raise ValueError('Created timestamp is in the future')
    if dt_expires < dt_now:
        raise ValueError('Envelope has expired')
