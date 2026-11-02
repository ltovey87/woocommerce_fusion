import base64
import hashlib
import hmac

from frappe.tests import UnitTestCase

from woocommerce_fusion.woocommerce_endpoint import is_ping, is_valid_signature

SECRET = "webhook-secret"
PAYLOAD = b'{"id": 123}'


def sign(secret: str, payload: bytes) -> str:
	return base64.b64encode(hmac.new(secret.encode(), payload, hashlib.sha256).digest()).decode()


class TestIsValidSignature(UnitTestCase):
	def test_should_accept_signature_made_with_the_secret(self):
		self.assertTrue(is_valid_signature(SECRET, PAYLOAD, sign(SECRET, PAYLOAD)))

	def test_should_reject_signature_made_with_another_secret(self):
		self.assertFalse(is_valid_signature(SECRET, PAYLOAD, sign("other", PAYLOAD)))

	def test_should_reject_signature_of_another_payload(self):
		self.assertFalse(is_valid_signature(SECRET, PAYLOAD, sign(SECRET, b'{"id": 456}')))

	def test_should_reject_missing_signature(self):
		self.assertFalse(is_valid_signature(SECRET, PAYLOAD, ""))

	def test_should_reject_when_no_secret_is_configured(self):
		self.assertFalse(is_valid_signature(None, PAYLOAD, sign("", PAYLOAD)))

	def test_should_reject_empty_payload(self):
		self.assertFalse(is_valid_signature(SECRET, b"", sign(SECRET, b"")))

	def test_should_reject_non_ascii_signature_without_raising(self):
		self.assertFalse(is_valid_signature(SECRET, PAYLOAD, "sïgnature"))


class TestIsPing(UnitTestCase):
	def test_should_recognise_woocommerce_ping(self):
		self.assertTrue(is_ping(b"webhook_id=42"))

	def test_should_not_treat_order_payload_as_ping(self):
		self.assertFalse(is_ping(PAYLOAD))

	def test_should_not_treat_ping_prefix_with_extra_data_as_ping(self):
		self.assertFalse(is_ping(b"webhook_id=42&id=123"))
