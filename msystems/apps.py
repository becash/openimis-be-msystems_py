from django.apps import AppConfig

DEFAULT_CFG = {
    # Should OpenIMIS verify signatures and timestamps of incoming soap messages
    "verify_incoming_soap_messages": True,
    # Mpass configurations
    "mpass_config": {
        "mpass_default_language": "ro",

        # URL to be redirected to after successful login
        "mpass_login_redirect": "",

        "mpass_key_first_name": "FirstName",
        "mpass_key_last_name": "LastName",
        "mpass_key_dob": "BirthDate",
        "mpass_key_roles": "Role",
        "mpass_key_legal_entities": "OrganizationAdministrator",
        "mpass_key_additional_legal_entity": "AdministeredEntities",
        # "mpass_key_legal_entities": "AdministeredLegalEntity",


        "saml_config": {
            # Strict mode: SAML responses must be validated strictly.
            "strict": True,
            # Set this to True for debugging purposes.
            "debug": False,
            # Service provider settings
            "sp": {
                # entityId, acs and sls urls are validated by IdP
                "entityId": "",
                # callback url for login attempts
                "assertionConsumerService": {
                    "url": "",
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                },
                # endpoint called from idp after logout
                "singleLogoutService": {
                    "url": "",
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                },
                # X509 certificate for the SP, PEM string format
                "x509cert": "",
                # RSA private key, PEM string format
                "privateKey": ""
            },
            "idp": {
                "entityId": "",
                # login endpoint to redirect from openIMIS
                "singleSignOnService": {
                    "url": "",
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                },
                # endpoint to call after logout from openIMIS
                "singleLogoutService": {
                    "url": "",
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                },
                # Idp public X509 certificate
                "x509cert": ""
            },
            # Advanced security options
            "security": {
                "authnRequestsSigned": True,
                "logoutRequestSigned": True,
                "logoutResponseSigned": True,
                "signMetadata": True,
            },
        }
    },
    # Mpay configurations
    "mpay_config": {
        "url": "",
        "payment_path": "service/pay",
        "bill_path": "front/bills/bill",
        "service_id": "SERVICE1",
        # The same as mpass cert
        "service_certificate": "",
        # The same as mpass private key
        "service_private_key": "",
        # Mpay certificate, PEM string format
        "mpay_certificate": "",
        # Default account info for voucher payments
        "mpay_split": "0.5",
        "mpay_destination_account_1": {
            "BankCode": "",
            "BankFiscalCode": "",
            "BankAccount": "",
            "BeneficiaryName": ""
        },
        "mpay_destination_account_2": {
            "BankCode": "",
            "BankFiscalCode": "",
            "BankAccount": "",
            "BeneficiaryName": ""
        }
    },
    # Mconnect configurations
    "mconnect_config": {
        "url": "",
        # The same as mpass cert
        "service_certificate": "",
        # The same as mpass private key
        "service_private_key": "",
        # Mconnect certificate, PEM string format
        "mconnect_certificate": "",

        # Get Person Soap Header default values
        "get_person_calling_user": "",  # len 13
        "get_person_calling_entity": "",  # len 13
        "get_person_call_basis": "",  # max len 256
        "get_person_call_reason": "",  # max len 512
    },
    "voucher_config": {
        # The same as mpass cert
        "service_certificate": "",
        # The same as mpass private key
        "service_private_key": "",
        # client_certificate, PEM string format
        "client_certificate": "",
    },
}


class MsystemsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "msystems"

    # DO NOT  CHANGE THIS ####
    ADMIN = "Admin"
    INSPECTOR = "Inspector"
    EMPLOYER = "Employer"
    IMIS_ADMIN = "IMIS Administrator"
    ENROLMENT_OFFICER = "Enrolment Officer"
    # ------------------ ####

    verify_incoming_soap_messages = None

    mpass_config = None
    mpay_config = None
    mconnect_config = None
    voucher_config = None

    def ready(self):
        from core.models import ModuleConfiguration

        cfg = ModuleConfiguration.get_or_default(self.name, DEFAULT_CFG)
        self._load_config(cfg)

    @classmethod
    def _load_config(cls, cfg):
        for field in cfg:
            if hasattr(MsystemsConfig, field):
                setattr(MsystemsConfig, field, cfg[field])
