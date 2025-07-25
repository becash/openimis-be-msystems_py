import decimal
import logging

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

from core import datetime
from invoice.apps import InvoiceConfig
from invoice.models import Bill, BillPayment
from msystems.apps import MsystemsConfig
from msystems.soap.datetime import SoapDatetime
from msystems.soap.models import OrderDetailsQuery, GetOrderDetailsResult, OrderLine, OrderDetails, \
    PaymentConfirmation, PaymentAccount, OrderStatus, CustomerType
from msystems.xml_utils import add_signature, verify_signature, verify_timestamp, add_timestamp
from policyholder.models import PolicyHolder
from worker_voucher.models import WorkerVoucher
from worker_voucher.services import worker_voucher_bill_user_filter

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


def _add_envelope_header(ctx):
    root = ctx.out_document

    add_timestamp(root)
    add_signature(root, MsystemsConfig.mpay_config['service_private_key'],
                  MsystemsConfig.mpay_config['service_certificate'])

    body = ctx.out_document.find('{http://schemas.xmlsoap.org/soap/envelope/}Body')
    ctx.out_document.remove(body)
    ctx.out_document.append(body)
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

        with transaction.atomic():
            for bill_item in bill.line_items_bill.filter(is_deleted=False):
                voucher = _get_voucher(bill_item)
                if voucher.status == WorkerVoucher.Status.AWAITING_PAYMENT:
                    if voucher.insuree is not None:
                        voucher.status = WorkerVoucher.Status.ASSIGNED
                    else:
                        voucher.status = WorkerVoucher.Status.UNASSIGNED
                    voucher.save(username=voucher.user_updated.username)

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
