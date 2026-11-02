import base64
import hashlib
import hmac
import json
import re
from http import HTTPStatus

import frappe
from frappe import _
from werkzeug.wrappers import Response

from woocommerce_fusion.tasks.sync_sales_orders import run_sales_order_sync
from woocommerce_fusion.woocommerce.woocommerce_api import (
	WC_RESOURCE_DELIMITER,
	parse_domain_from_url,
)

WEBHOOK_PING_PATTERN = re.compile(rb"webhook_id=\d+")


def validate_request() -> tuple[bool, HTTPStatus | None, str | None]:
	# Get relevant WooCommerce Server
	try:
		webhook_source_url = frappe.get_request_header("x-wc-webhook-source", "")
		wc_server = frappe.get_doc("WooCommerce Server", parse_domain_from_url(webhook_source_url))
	except Exception:
		return False, HTTPStatus.BAD_REQUEST, _("Missing Header")

	signature = frappe.get_request_header("x-wc-webhook-signature", "")
	if not is_valid_signature(wc_server.secret, frappe.request.data, signature):
		return False, HTTPStatus.UNAUTHORIZED, _("Unauthorized")

	frappe.set_user(wc_server.creation_user)  # nosemgrep
	return True, None, None


def is_valid_signature(secret: str | None, payload: bytes, signature: str) -> bool:
	if not secret or not payload:
		return False
	expected = base64.b64encode(hmac.new(secret.encode("utf8"), payload, hashlib.sha256).digest())
	return hmac.compare_digest(expected, signature.encode("utf8"))


def is_ping(payload: bytes) -> bool:
	return WEBHOOK_PING_PATTERN.fullmatch(payload) is not None


@frappe.whitelist(allow_guest=True, methods=["POST"])  # nosemgrep
def order_created(*args, **kwargs):
	"""
	Accepts payload data from WooCommerce "Order Created" webhook
	"""
	# WooCommerce pings new webhooks without a signature or source header. Answering does
	# nothing, so it needs no authentication and must not reach validate_request.
	if frappe.request and is_ping(frappe.request.data):
		return Response(status=HTTPStatus.OK)

	valid, status, msg = validate_request()
	if not valid:
		return Response(response=msg, status=status)

	if frappe.request and frappe.request.data:
		try:
			order = json.loads(frappe.request.data)
		except ValueError:
			# woocommerce returns 'webhook_id=value' for the first request which is not JSON
			order = frappe.request.data
		event = frappe.get_request_header("x-wc-webhook-event")
	else:
		return Response(response=_("Missing Header"), status=HTTPStatus.BAD_REQUEST)

	if event == "created":
		webhook_source_url = frappe.get_request_header("x-wc-webhook-source", "")
		server_domain = parse_domain_from_url(webhook_source_url)
		woocommerce_order_name = f"{server_domain}{WC_RESOURCE_DELIMITER}{order['id']}"
		server = frappe.get_cached_doc("WooCommerce Server", server_domain)
		if server.enable_batch_api:
			from woocommerce_fusion.woocommerce.doctype.woocommerce_sync_queue.woocommerce_sync_queue import (
				enqueue_order,
			)

			enqueue_order(
				woocommerce_server=server_domain,
				woocommerce_order_id=str(order["id"]),
				direction="inbound",
				triggered_by="Hook",
			)
		else:
			frappe.enqueue(run_sales_order_sync, queue="long", woocommerce_order_name=woocommerce_order_name)
		return Response(status=HTTPStatus.OK)
	else:
		return Response(response=_("Event not supported"), status=HTTPStatus.BAD_REQUEST)
