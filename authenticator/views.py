import json
import uuid

from django.views.generic.base import View
from django.http.response import HttpResponse, JsonResponse
from django.conf import settings
from django.contrib import messages
from django.shortcuts import redirect
from django.contrib.auth import authenticate, login
from django.core.exceptions import ValidationError

from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
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
    PublicKeyCredentialDescriptor,
    UserVerificationRequirement,
    AuthenticationCredential,
)
from webauthn.helpers.exceptions import InvalidRegistrationResponse, InvalidAuthenticationResponse

from authenticator.forms import LoginSessionForm, RegistrationSessionForm
from .models import Credential, LoginSession, RegistrationSession, User

import logging

logger = logging.getLogger('authenticator.logger')

RP_ID = settings.RP_ID
RP_NAME = settings.RP_NAME


# authenticator serves the endpoints for registration and
# authentication domain/api/*


def createSession(form_class, request):
    """
    Create temporary session on a register/login request that has not yet
    been confirmed by biometrics.
    """

    form = form_class(request.POST)
    try:
        session = form.save()
        session_id = session.id
        return JsonResponse({'id': session_id})
    except Exception as e:
        if form.has_error and 'username' in form.errors:
            # set messages to be displayed in template
            messages.error(request, form.errors['username'])
            return redirect(request.path)
        logger.exception(e)
        return HttpResponse(status=500)


# respond on POST req, return forbidden on GET
class RegisterRequestView(View):
    """
    Answer to a biometrics register request sending options to initiate the registration.
    """

    def post(self, request):
        try:
            session_id = request.GET['id']
            password = request.POST['password']
            
            # check that temp session exists and password matches
            username = RegistrationSession.objects.get(id=session_id).username
            registration_session = authenticate(request, username=username, password=password)
            if not registration_session:
                messages.error(request, 'User could not be authenticated, try again.')
                # response to ajax request
                return HttpResponse(status=401)
            
            user_id = uuid.uuid4().hex
            user_name = registration_session.username
            
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
        except RegistrationSession.DoesNotExist as e:
            messages.error(request, "Invalid session")
            return HttpResponse(status=401)
        except ValidationError as e:
            messages.error(request, "Invalid session")
            return HttpResponse(status=401)
        except Exception as e:
            logger.exception(e)
            messages.error(request, "Internal error")
            return HttpResponse(status=500)
            


class RegisterResponseView(View):
    """
    Verifies correctness of client response and completes the registration.
    """

    def post(self, request):
        credential = json.loads(request.POST['credential'])

        try:
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
            request.session.flush()
            
            registration_session = RegistrationSession.objects.get(pk=session_id)
            username = registration_session.username
            # set session status
            registration_session.username = user_id
            registration_session.completed = True
            registration_session.save()
            
            new_user = User(id=user_id, username=username)
            new_user.password = registration_session.password
            
            # save authenticator
            new_credential = Credential(
                user=new_user,
                credential_id=bytes_to_base64url(registration_verification.credential_id),
                credential_public_key=bytes_to_base64url(registration_verification.credential_public_key)
                )
            
            new_user.save()
            new_credential.save()

            return HttpResponse(status=200)
        
        except InvalidRegistrationResponse as e:
            logger.exception(e)
            messages.error(request, 'Authenticator could not be verified')
            return HttpResponse(status=401)
        except Exception as e:
            logger.exception(e)
            return HttpResponse(status=500)
    
    
class LoginRequestView(View):
    """
    Answer to a biometrics register request sending options to initiate the login.
    """

    def post(self, request):
        try:
            session_id = request.GET['id']
            login_session = LoginSession.objects.get(id=session_id)
            user = login_session.user
        
            # get registered user credentials and generate authentication options.
            user_credentials = Credential.objects.filter(user_id=user.id)
            allow_credentials = [
                PublicKeyCredentialDescriptor(id=base64url_to_bytes(c.credential_id))
                for c in user_credentials
                ]
            
            authentication_options = generate_authentication_options(
                rp_id=RP_ID,
                allow_credentials=allow_credentials,
                user_verification=UserVerificationRequirement.REQUIRED,
            )
            
            # save challenge in session to be verified later
            request.session['challenge'] = bytes_to_base64url(authentication_options.challenge)
            request.session['session_id'] = session_id

            return JsonResponse(json.loads(options_to_json(authentication_options)))
        
        except Exception as e:
            logger.exception(e)
            return HttpResponse(status=500)
            

class LoginResponseView(View):
    """
    Verifies correctness of client response and completes the login.
    """
    
    def post(self, request):
        try:
            credential = json.loads(request.POST['credential'])
            
            session_id = request.session['session_id']
            login_session = LoginSession.objects.get(id=session_id)
            
            saved_credential = Credential.objects.get(
                user_id=login_session.user.id, 
                credential_id=credential['id']
                )

            # Authentication Response Verification
            # verify that the signature in client response was signed with the private key 
            # corresponding to the public key saved in DB at registration time
            authentication_verification = verify_authentication_response(
                credential=AuthenticationCredential.parse_raw(
                    f"""{{
                        "id": "{credential['id']}",
                        "rawId": "{credential['rawId']}",
                        "response": {{
                            "authenticatorData": "{credential['response']['authenticatorData']}",
                            "clientDataJSON": "{credential['response']['clientDataJSON']}",
                            "signature": "{credential['response']['signature']}",
                            "userHandle": "{credential['response']['userHandle']}"
                        }},
                        "type": "{credential['type']}",
                        "clientExtensionResults": "{{}}"
                    }}"""
                ),
                expected_challenge=base64url_to_bytes(request.session['challenge']),
                expected_origin=f"https://{RP_ID}:8000",
                expected_rp_id=RP_ID,
                credential_public_key=base64url_to_bytes(saved_credential.credential_public_key),
                credential_current_sign_count=0,
                require_user_verification=True,
            )
            request.session.flush()

            # set session status
            login_session.completed = True
            login_session.save()
            
            return HttpResponse(status=200)
        except InvalidAuthenticationResponse as e:
            logger.exception(e)
            messages.error(request, 'Authenticator could not be validated')
            return HttpResponse(status=401)
        except Exception as e:
            logger.exception(e)
            return HttpResponse(status=500)


class PollingView(View):
    """
    Views responding to polling requests from desktop client 
    to know if a registration/login was successful.
    """
    
    async def post(self, request):
        try:
            session_type = request.POST['type']
            session_id = request.POST['id']
            session = None
            if session_type == "registration":
                session = await RegistrationSession.objects.aget(id=session_id)
            elif session_type == "login":
                session = await LoginSession.objects.aget(id=session_id)
            if session is not None and session.completed:
                return HttpResponse("completed", status=200)
            else:
                return HttpResponse("not completed", status=200)
        except RegistrationSession.DoesNotExist as e:
            return HttpResponse("not completed", status=200)
        except LoginSession.DoesNotExist as e:
            return HttpResponse("not completed", status=200)
        except Exception as e:
            logger.exception(e)
            return HttpResponse(status=500)


def registrationCompleted(request, session_id):
    try:
        session = RegistrationSession.objects.get(id=session_id)
        if session.completed:
            session.delete()
            return HttpResponse(True, status=200)
        return HttpResponse(False, status=200)
    except RegistrationSession.DoesNotExist as e:
        return HttpResponse(False, status=200)
    except Exception as e:
        logger.exception(e)
        return HttpResponse(status=500)
    


def userLogin(request, session_id):
    try:
        session = LoginSession.objects.get(id=session_id)
        if session.completed:
            login(request, session.user)
            session.delete()
        return HttpResponse(status=200)
    except LoginSession.DoesNotExist as e:
        return HttpResponse(status=200)
    except Exception as e:
        logger.exception(e)
        return HttpResponse(status=500)
