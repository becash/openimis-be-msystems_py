import decimal
import logging
import uuid
from base64 import b64encode
import base64
from xml.sax.saxutils import escape

from lxml import etree
from django.db import transaction
from django.views.decorators.http import require_GET
from django.http import HttpResponseNotFound, JsonResponse
from django.contrib.contenttypes.models import ContentType
from rest_framework.decorators import api_view
from spyne.application import Application
from spyne.decorator import rpc
from spyne.model.fault import Fault
from spyne.protocol.soap import Soap11
from spyne.server.django import DjangoApplication
from spyne.service import ServiceBase
from urllib.parse import urljoin
from zeep.exceptions import SignatureVerificationFailed
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import hashlib

from core import datetime
from invoice.apps import InvoiceConfig
from invoice.models import Bill, BillPayment
from msystems.apps import MsystemsConfig
from msystems.soap.datetime import SoapDatetime
from msystems.soap.models import OrderDetailsQuery, GetOrderDetailsResult, OrderLine, OrderDetails, \
    PaymentConfirmation, PaymentAccount, OrderStatus, CustomerType
from msystems.xml_utils import add_signature, verify_signature, verify_timestamp, add_timestamp, ns_wss_util, ns_wss_s, \
    ns_envelope
from policyholder.models import PolicyHolder
from worker_voucher.models import WorkerVoucher
from worker_voucher.services import worker_voucher_bill_user_filter, economic_unit_user_filter
from django.db.models import Q

namespace = 'https://mpay.gov.md'
logger = logging.getLogger(__name__)

_order_status_map = {
    Bill.Status.DRAFT: OrderStatus.Expired,
    Bill.Status.VALIDATED: OrderStatus.Active,
    Bill.Status.PAID: OrderStatus.Paid,
    Bill.Status.CANCELLED: OrderStatus.Canceled,
    Bill.Status.DELETED: OrderStatus.Canceled,
    Bill.Status.SUSPENDED: OrderStatus.Canceled,
    Bill.Status.UNPAID: OrderStatus.Expired,
    Bill.Status.RECONCILIATED: OrderStatus.Paid
}


def _check_service_id(service_id):
    if service_id != MsystemsConfig.mpay_config['service_id']:
        raise Fault(faultcode='UnknownService', faultstring=f'ServiceID "{service_id} is unknown')


def _get_order(order_key):
    bill = Bill.objects.filter(code__iexact=order_key,
                               subject_type=ContentType.objects.get_for_model(PolicyHolder)).first()
    if not bill:
        raise Fault(faultcode='InvalidParameter', faultstring=f'OrderKey "{order_key}" is unknown')
    return bill


def _get_order_line(bill, line_id):
    bill_item = bill.line_items_bill.filter(code__iexact=line_id).first()
    if not bill_item:
        raise Fault(faultcode='InvalidParameter', faultstring=f'LineID "{line_id}" is unknown')
    return bill_item


def _check_amount_due(bill_item, amount_due):
    if amount_due != bill_item.amount_total:
        raise Fault(faultcode='InvalidParameter',
                    faultstring=f'Amount "{amount_due}" does not match the order line {bill_item.code}')

def _check_due_date(bill):
    now = datetime.datetime.now()
    if not now < bill.date_due:
        raise Fault(faultcode='InvalidParameter',
                    faultstring=f'Order {bill.code} has expired on {bill.date_due}')


def _get_voucher(bill_item):
    voucher = WorkerVoucher.objects.filter(id=bill_item.line_id).first()
    if not voucher:
        raise Fault(faultcode='InvalidParameter',
                    faultstring=f'Voucher {bill_item.line_id} for order line {bill_item.code} not found')
    return voucher


def _log_rpc_call(ctx):
    input = ctx.transport.req.get('wsgi.input')
    action = ctx.transport.req.get('HTTP_SOAPACTION')
    if input:
        input.seek(0)
        data = input.read().decode("utf-8")
        logger.info(f"Method {action} called with:\n{data}\n")
        input.seek(0)


def _validate_envelope(ctx):
    root = ctx.in_document

    try:
        verify_timestamp(root)
    except ValueError as e:
        logger.error("Timestamp verification failed", exc_info=e)
        raise Fault(faultcode='InvalidRequest', faultstring=str(e))

    try:
        verify_signature(root, MsystemsConfig.mpay_config['mpay_certificate'])
    except SignatureVerificationFailed as e:
        logger.error("Envelope signature verification failed", exc_info=e)
        raise Fault(faultcode='InvalidRequest', faultstring='Envelope signature verification failed')


def _canonicalize_element(element):
    """Canonicalize element using C14N exclusive canonicalization"""
    return etree.tostring(element, method="c14n", exclusive=True, with_comments=False)


def _create_digest(element):
    """Create SHA-1 digest of canonicalized element"""
    canonical_xml = _canonicalize_element(element)
    digest = hashlib.sha1(canonical_xml).digest()
    return base64.b64encode(digest).decode('utf-8')


def _create_signed_info(body_id, timestamp_id=None):
    """Create SignedInfo element for WS-Security signature"""
    signed_info = etree.Element(etree.QName("http://www.w3.org/2000/09/xmldsig#", "SignedInfo"))

    # CanonicalizationMethod
    canonicalization_method = etree.SubElement(
        signed_info,
        etree.QName("http://www.w3.org/2000/09/xmldsig#", "CanonicalizationMethod")
    )
    canonicalization_method.set("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#")

    # SignatureMethod
    signature_method = etree.SubElement(
        signed_info,
        etree.QName("http://www.w3.org/2000/09/xmldsig#", "SignatureMethod")
    )
    signature_method.set("Algorithm", "http://www.w3.org/2000/09/xmldsig#rsa-sha1")

    return signed_info


def _add_reference(signed_info, element_id, digest_value):
    """Add Reference element to SignedInfo"""
    reference = etree.SubElement(
        signed_info,
        etree.QName("http://www.w3.org/2000/09/xmldsig#", "Reference")
    )
    reference.set("URI", f"#{element_id}")

    # Transforms
    transforms = etree.SubElement(
        reference,
        etree.QName("http://www.w3.org/2000/09/xmldsig#", "Transforms")
    )
    transform = etree.SubElement(
        transforms,
        etree.QName("http://www.w3.org/2000/09/xmldsig#", "Transform")
    )
    transform.set("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#")

    # DigestMethod
    digest_method = etree.SubElement(
        reference,
        etree.QName("http://www.w3.org/2000/09/xmldsig#", "DigestMethod")
    )
    digest_method.set("Algorithm", "http://www.w3.org/2000/09/xmldsig#sha1")

    # DigestValue
    digest_value_elem = etree.SubElement(
        reference,
        etree.QName("http://www.w3.org/2000/09/xmldsig#", "DigestValue")
    )
    digest_value_elem.text = digest_value

    return reference


def _sign_signed_info(signed_info, private_key):
    """Sign the SignedInfo using RSA-SHA1"""
    # Canonicalize SignedInfo
    canonical_signed_info = _canonicalize_element(signed_info)

    # Parse private key if it's a string
    if isinstance(private_key, str):
        private_key_obj = serialization.load_pem_private_key(
            private_key.encode('utf-8'),
            password=None,
            backend=default_backend()
        )
    else:
        private_key_obj = private_key

    # Sign using PKCS1v15 with SHA1
    signature = private_key_obj.sign(
        canonical_signed_info,
        padding.PKCS1v15(),
        hashes.SHA1()
    )

    return base64.b64encode(signature).decode('utf-8')


def add_ws_security_signature(root, private_key, certificate, cert_id="X509Token"):
    """
    Add WS-Security signature with SecurityTokenReference according to IBM WebSphere standards
    """
    # Find or create Security header
    security = root.find(f".//{{{ns_wss_s}}}Security")
    if security is None:
        header = root.find(f".//{{{ns_envelope}}}Header")
        if header is None:
            header = etree.SubElement(root, etree.QName(ns_envelope, "Header"))
        security = etree.SubElement(header, etree.QName(ns_wss_s, "Security"))

    # Add BinarySecurityToken if not present
    binary_token = security.find(f".//{{{ns_wss_s}}}BinarySecurityToken")
    if binary_token is None:
        # Parse certificate to get DER data
        if isinstance(certificate, str):
            cert_obj = x509.load_pem_x509_certificate(
                certificate.encode('utf-8'),
                default_backend()
            )
            cert_der = cert_obj.public_bytes(serialization.Encoding.DER)
        else:
            cert_der = certificate

        b64_cert = base64.b64encode(cert_der).decode('utf-8')

        binary_token = etree.SubElement(security, etree.QName(ns_wss_s, "BinarySecurityToken"))
        binary_token.set("EncodingType",
                         "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary")
        binary_token.set("ValueType",
                         "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3")
        binary_token.set(etree.QName(ns_wss_util, "Id"), cert_id)
        binary_token.text = b64_cert

    # Get elements to sign
    body = root.find(f".//{{{ns_envelope}}}Body")
    timestamp = security.find(f".//{{{ns_wss_util}}}Timestamp")

    if body is None:
        return

    # Add IDs if missing
    body_id = body.get(etree.QName(ns_wss_util, "Id"))
    if not body_id:
        body_id = f"Body-{uuid.uuid4().hex[:8]}"
        body.set(etree.QName(ns_wss_util, "Id"), body_id)

    timestamp_id = None
    if timestamp is not None:
        timestamp_id = timestamp.get(etree.QName(ns_wss_util, "Id"))
        if not timestamp_id:
            timestamp_id = f"Timestamp-{uuid.uuid4().hex[:8]}"
            timestamp.set(etree.QName(ns_wss_util, "Id"), timestamp_id)

    # Create Signature element
    signature = etree.SubElement(security, etree.QName("http://www.w3.org/2000/09/xmldsig#", "Signature"))

    # Create SignedInfo
    signed_info = _create_signed_info(body_id, timestamp_id)
    signature.append(signed_info)

    # Add reference to Body
    body_digest = _create_digest(body)
    _add_reference(signed_info, body_id, body_digest)

    # Add reference to Timestamp if present
    if timestamp is not None and timestamp_id:
        timestamp_digest = _create_digest(timestamp)
        _add_reference(signed_info, timestamp_id, timestamp_digest)

    # Sign the SignedInfo
    signature_value = _sign_signed_info(signed_info, private_key)

    # Add SignatureValue
    signature_value_elem = etree.SubElement(
        signature,
        etree.QName("http://www.w3.org/2000/09/xmldsig#", "SignatureValue")
    )
    signature_value_elem.text = signature_value

    # Add KeyInfo with SecurityTokenReference
    key_info = etree.SubElement(
        signature,
        etree.QName("http://www.w3.org/2000/09/xmldsig#", "KeyInfo")
    )

    security_token_ref = etree.SubElement(
        key_info,
        etree.QName(ns_wss_s, "SecurityTokenReference")
    )

    # Reference to BinarySecurityToken
    wsse_reference = etree.SubElement(
        security_token_ref,
        etree.QName(ns_wss_s, "Reference")
    )
    wsse_reference.set("URI", f"#{cert_id}")
    wsse_reference.set("ValueType",
                       "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3")

    # Ensure proper ordering: Timestamp, BinarySecurityToken, Signature
    timestamp = security.find(f".//{{{ns_wss_util}}}Timestamp")
    binary_token = security.find(f".//{{{ns_wss_s}}}BinarySecurityToken")

    if timestamp is not None:
        security.remove(timestamp)
        security.insert(0, timestamp)

    if binary_token is not None:
        security.remove(binary_token)
        if timestamp is not None:
            security.insert(1, binary_token)
        else:
            security.insert(0, binary_token)

    signature = security.find(f".//{{'http://www.w3.org/2000/09/xmldsig#'}}Signature")
    if signature is not None:
        security.remove(signature)
        security.append(signature)


def _add_envelope_header(ctx):
    root = ctx.out_document

    add_timestamp(root)

    # Add WS-Security signature according to IBM WebSphere standards
    add_ws_security_signature(
        root,
        MsystemsConfig.mpay_config['service_private_key'],
        MsystemsConfig.mpay_config['service_certificate']
    )

    envelope = etree.tostring(ctx.out_document, pretty_print=True)
    logger.info(envelope.decode('utf-8'))
    ctx.out_string = [envelope]


class MpayService(ServiceBase):
    @rpc(OrderDetailsQuery.customize(min_occurs=1, max_occurs=1, nillable=False),
         _returns=GetOrderDetailsResult.customize(min_occurs=1, max_occurs=1, nillable=False))
    def GetOrderDetails(ctx, query: OrderDetailsQuery) -> GetOrderDetailsResult:
        _check_service_id(query.ServiceID)
        bill = _get_order(query.OrderKey)

        split = decimal.Decimal(MsystemsConfig.mpay_config['mpay_split'])
        account1 = PaymentAccount(**MsystemsConfig.mpay_config['mpay_destination_account_1'])
        account2 = PaymentAccount(**MsystemsConfig.mpay_config['mpay_destination_account_2'])

        order_lines = []
        for bill_item in bill.line_items_bill.filter(is_deleted=False):
            amount1 = round(bill_item.amount_total * split, 2)
            # Split the amount into two lines
            # Use only first 2 sections of the code (uuid),max char limit is 36, full len code is 38
            # The line should be easily identifiable in context of OrderId (bill code)
            order_lines.append(OrderLine(AmountDue=str(amount1),
                                         LineID=bill_item.code[:13] + "_1",
                                         Reason="Voucher Acquirement",
                                         DestinationAccount=account1))
            amount2 = round(bill_item.amount_total - amount1, 2)
            order_lines.append(OrderLine(AmountDue=amount2,
                                         LineID=bill_item.code[:13] + "_2",
                                         Reason="Voucher Acquirement",
                                         DestinationAccount=account2))

        if not order_lines:
            raise Fault(faultcode='InvalidParameter', faultstring=f'OrderKey "{query.OrderKey}" has no line items')

        order_details = OrderDetails(
            CustomerID=bill.subject.code,
            CustomerType=CustomerType.Organization,
            CustomerName=bill.subject.trade_name,
            Currency=InvoiceConfig.default_currency_code,
            Lines=order_lines,
            OrderKey=bill.code,
            Reason="Voucher Acquirement",
            ServiceID=query.ServiceID,
            Status=_order_status_map[bill.status],
            TotalAmountDue=str(bill.amount_total),
            IssuedAt=SoapDatetime.from_ad_datetime(bill.date_created),
            DueDate=SoapDatetime.from_ad_date(bill.date_due),
        )

        ret = GetOrderDetailsResult(OrderDetails=order_details)
        return ret

    @rpc(PaymentConfirmation.customize(min_occurs=1, max_occurs=1, nillable=False))
    def ConfirmOrderPayment(ctx, confirmation: PaymentConfirmation) -> None:
        _check_service_id(confirmation.ServiceID)
        bill = _get_order(confirmation.OrderKey)
        _check_amount_due(bill, decimal.Decimal(confirmation.TotalAmount))
        _check_due_date(bill)

        # Get all unpaid vouchers for the specified month (status AWAITING_PAYMENT)
        unpaid_vouchers = WorkerVoucher.objects.filter(
            Q(bill_code=bill.code)
        )

        with transaction.atomic():
            if bill.status != Bill.Status.PAID:
                bill.status = Bill.Status.PAID
                bill.date_payed = confirmation.PaidAt
                bill.save(username=bill.user_updated.username)

            payment = BillPayment.objects.filter(bill=bill, code_tp=confirmation.PaymentID).first()
            if not payment:
                payment = BillPayment(bill=bill)
                payment.code_tp = confirmation.PaymentID
                payment.code_ext = confirmation.InvoiceID
                payment.status = BillPayment.PaymentStatus.ACCEPTED
                payment.date_payment = confirmation.PaidAt
                payment.amount_payed = bill.amount_total
                payment.amount_received = bill.amount_total
                payment.payment_origin = "Mpay"
                payment.save(username=bill.user_updated.username)


def _error_handler_function(ctx, *args, **kwargs):
    logger.error("Spyne error", exc_info=ctx.in_error)


_application = Application(
    [MpayService],
    tns=namespace,
    in_protocol=Soap11(validator='lxml'),
    out_protocol=Soap11(),
)
_application.event_manager.add_listener('method_call', _validate_envelope)
_application.event_manager.add_listener('method_exception_object', _error_handler_function)

mpay_app = DjangoApplication(_application)
mpay_app.event_manager.add_listener('wsgi_call', _log_rpc_call)
mpay_app.event_manager.add_listener('wsgi_return', _add_envelope_header)


@require_GET
@api_view(['GET'])
def mpay_bill_payment_redirect(request):
    bill_id = request.GET.get('bill')
    bill = worker_voucher_bill_user_filter(Bill.objects.filter(id=bill_id, is_deleted=False), request.user).first()
    if not bill:
        return HttpResponseNotFound()

    host = f"{request.scheme}://{request.get_host()}/"
    bill_path = f"{MsystemsConfig.mpay_config['bill_path']}/{bill_id}/"
    redirect_back_url = urljoin(host, bill_path)
    redirect_url = urljoin(MsystemsConfig.mpay_config['url'], MsystemsConfig.mpay_config['payment_path'])

    return JsonResponse({
        "url": redirect_url,
        "args": {
            "OrderKey": bill.code,
            "ServiceID": MsystemsConfig.mpay_config['service_id'],
            "ReturnUrl": redirect_back_url
        }
    })