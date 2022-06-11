import json

from django.views.generic.base import View
from django.http.response import HttpResponse, JsonResponse
from django.conf import settings

from webauthn import (
    generate_registration_options,
    verify_registration_response,
    options_to_json,
    base64url_to_bytes,
)
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorAttachment,
    AuthenticatorSelectionCriteria,
    ResidentKeyRequirement,
    RegistrationCredential,
)
from webauthn.helpers import bytes_to_base64url


RP_ID = settings.RP_ID
RP_NAME = settings.RP_NAME


# authenticator serves the endpoints for registration and
# authentication domain/api/*

# respond on POST req, return forbidden on GET
class RegisterRequestView(View):

    def post(self, request):
        
        registration_options = generate_registration_options(
            rp_id=RP_ID,
            rp_name=RP_NAME,
            user_id="12345",
            user_name=request.POST['user_name'],
            attestation=AttestationConveyancePreference.DIRECT,
            authenticator_selection=AuthenticatorSelectionCriteria(
                authenticator_attachment=AuthenticatorAttachment.PLATFORM,
                resident_key=ResidentKeyRequirement.REQUIRED,
            ),
        )

        # save challenge in session to be verified later
        request.session['challenge'] = bytes_to_base64url(registration_options.challenge)

        return JsonResponse(json.loads(options_to_json(registration_options)))


class RegisterResponseView(View):

    def post(self, request):
        credential = json.loads(request.POST['credential'])

        if 'response' not in credential:
            pass

        # Registration Response Verification
        registration_verification = verify_registration_response(
            credential=RegistrationCredential.parse_raw(
                f"""{{
                    "id": "{credential['id']}",
                    "rawId": "{credential['rawId']}",
                    "response": {{
                        "attestationObject": "{credential['response']['attestationObject']}",
                        "clientDataJSON": "{credential['response']['clientDataJSON']}"
                    }},
                    "type": "{credential['type']}"
                }}"""
            ),
            expected_challenge=base64url_to_bytes(request.session['challenge']),
            expected_origin=f"https://{RP_ID}:8000",
            expected_rp_id=RP_ID,
            require_user_verification=True,
        )
        del request.session['challenge']

        # TODO: save user to DB

        return HttpResponse(status=200)
