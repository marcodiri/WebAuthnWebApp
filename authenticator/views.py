import json
import base64
import uuid
import qrcode
from io import BytesIO
from urllib.parse import urlencode

from django.views.generic.base import View
from django.http.response import HttpResponse, HttpResponseRedirect, JsonResponse
from django.conf import settings
from django.contrib import messages
from django.shortcuts import redirect
from django.urls import reverse
from django.contrib.auth import authenticate

from webauthn import (
    generate_registration_options,
    verify_registration_response,
    options_to_json,
    base64url_to_bytes,
)
from webauthn.helpers import bytes_to_base64url
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorAttachment,
    AuthenticatorSelectionCriteria,
    ResidentKeyRequirement,
    RegistrationCredential,
)

from authenticator.forms import TempSessionForm
from .models import Credential, TempSession, User

import logging

logger = logging.getLogger('authenticator.logger')

RP_ID = settings.RP_ID
RP_NAME = settings.RP_NAME


# authenticator serves the endpoints for registration and
# authentication domain/api/*

# respond on POST req, return forbidden on GET
def registerMiddlewareView(request):
    """
    Create temporary session on a register request that has not yet
    been confirmed by biometrics.
    """

    form = TempSessionForm(request.POST)
    try:
        temp_session = form.save()
        session_id = temp_session.id
        # generate QR with redirect url
        host = request.get_host()
        path = reverse('webapp:register_biometrics')
        query = urlencode({'id': session_id})
        url = f'https://{host}{path}?{query}'
        qr = qrcode.QRCode(
            version=1,
            box_size=6,
            border=3
            )
        qr.add_data(url)
        qr.make(fit=True)
        img = qr.make_image(fill='black', back_color='white')
        # convert qr image to base64
        buffered = BytesIO()
        img.save(buffered, format="JPEG")
        img_bytes = base64.b64encode(buffered.getvalue())
        return JsonResponse({'session_id': session_id, 'qrcodeB64': img_bytes.decode()})
    except Exception as e:
        if form.has_error and 'username' in form.errors:
            # set messages to be displayed in template
            messages.error(request, form.errors['username'])
            return redirect(request.path)
        else:
            return HttpResponse(str(e), status=500)

class RegisterRequestView(View):
    """
    Answer to a biometrics register request sending options to initiate the registration.
    """

    def post(self, request):
        session_id = request.GET['id']
        password = request.POST['password']
        
        # check that temp session exists and password matches
        temp_session = authenticate(request, username=session_id, password=password)
        if not temp_session:
            messages.error(request, 'User could not be authenticated, try again.')
            # response to ajax request, so cannot redirect directly. Do redirection on the client.
            return HttpResponse(status=302)
        
        user_id = uuid.uuid4().hex
        user_name = temp_session.username
        
        registration_options = generate_registration_options(
            rp_id=RP_ID,
            rp_name=RP_NAME,
            user_id=user_id,
            user_name=user_name,
            attestation=AttestationConveyancePreference.DIRECT,
            authenticator_selection=AuthenticatorSelectionCriteria(
                authenticator_attachment=AuthenticatorAttachment.PLATFORM,
                resident_key=ResidentKeyRequirement.REQUIRED,
            ),
        )
        request.session['session_id'] = session_id
        request.session['user_id'] = user_id
        # save challenge in session to be verified later
        request.session['challenge'] = bytes_to_base64url(registration_options.challenge)

        return JsonResponse(json.loads(options_to_json(registration_options)))


class RegisterResponseView(View):
    """
    Verifies correctness of client response and completes the registration.
    """

    def post(self, request):
        credential = json.loads(request.POST['credential'])

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

        session_id = request.session['session_id']
        user_id = request.session['user_id']
        try:
            temp_session = TempSession.objects.get(pk=session_id)
            # delete temp session
            temp_session.delete()
            request.session.flush()
            
            new_user = User(id=user_id, username=temp_session.username)
            new_user.password = temp_session.password
            
            # save authenticator
            new_credential = Credential(
                user=new_user,
                credential_id=bytes_to_base64url(registration_verification.credential_id),
                credential_public_key=bytes_to_base64url(registration_verification.credential_public_key)
                )
            
            new_user.save()
            new_credential.save()
            
        except Exception as e:
            logger.exception(e)
            return HttpResponse(status=500)

        return HttpResponse(status=200)
