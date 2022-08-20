import json
import logging
import base64
from urllib import request
import qrcode
from io import BytesIO
from urllib.parse import urlencode

from django.http import HttpResponse
from django.views.generic import TemplateView
from django.shortcuts import render, redirect
from django.urls import reverse
from django.contrib.auth import logout

from authenticator.forms import LoginSessionForm, RegistrationSessionForm
from authenticator.views import createSession, registrationCompleted, userLogin


logger = logging.getLogger('webapp.logger')


class InputView(TemplateView):
    redir_path = None
    
    def generate_qr(self, host, path, session_id):
            # generate QR with redirect url
            params = urlencode({'id': session_id})
            url = f'https://{host}{path}?{params}'
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
            return img_bytes.decode()
        
    
    def get(self, request, *args, **kwargs):
        if 'id' in request.session:
            if self.redir_path is None:
                return HttpResponse(status=500)
            session_id = request.session['id']
            del request.session['id']
            context = {
                'id': session_id,
                'qrcodeB64': self.generate_qr(request.get_host(), 
                                              reverse(self.redir_path), 
                                              session_id),
            }
            return render(request, self.template_name, context=context)
        else:
            form = self.form_class()
            return render(request, self.template_name, context={'form': form,})
    
    def post(self, request, *args, **kwargs):
        response = createSession(self.form_class, request)

        if response.status_code == 200:
            request.session['id'] = json.loads(response.content.decode('utf-8'))['id']
            return redirect(request.path)
        elif response.status_code == 302:
            return redirect(response.url)
        else:
            return HttpResponse(status=500)


class RegisterView(InputView):
    form_class = RegistrationSessionForm
    template_name = 'webapp/register.html'
    redir_path = 'webapp:register_biometrics'
    

class RegisterBiometricsView(TemplateView):
    template_name = 'webapp/register_biometrics.html'


class LoginView(InputView):
    form_class = LoginSessionForm
    template_name = 'webapp/login.html'
    redir_path = 'webapp:login_biometrics'


class LoginBiometricsView(TemplateView):
    template_name = 'webapp/login_biometrics.html'


class RegistrationCompletedView(TemplateView):
    template_name = 'webapp/registration_completed.html'
    
    def get(self, request):
        status = False
        if "id" in request.GET:
            session_id = request.GET['id']
            status = registrationCompleted(request, session_id)
            context = {'status': status}
            return render(request, self.template_name, context=context)
        else:
            return redirect("/register")


class IndexView(TemplateView):
    template_name = 'webapp/index.html'
    
    def get(self, request):
        if 'id' in request.GET:
            session_id = request.GET['id']
            userLogin(request, session_id)
            user = request.user
        return render(request, self.template_name)


def userLogout(request):
    if request.user.is_authenticated:
        logout(request)
    return redirect("/")

