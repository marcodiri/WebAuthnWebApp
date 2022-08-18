import json
import logging

from django.http import HttpResponse
from django.views.generic import TemplateView
from django.contrib import messages
from django.shortcuts import render, redirect

from authenticator.forms import LoginForm, RegistrationSessionForm
from authenticator.views import loginMiddlewareView, registerMiddlewareView

logger = logging.getLogger('webapp.logger')


class InputView(TemplateView):
    response_fn = None
    
    def get(self, request, *args, **kwargs):
        if 'id' in request.session:
            id = request.session['id']
            qrcodeB64 = request.session['qrcodeB64']
            del request.session['id']
            del request.session['qrcodeB64']
            context = {
                'id': id,
                'qrcodeB64': qrcodeB64,
            }
            return render(request, self.template_name, context=context)
        else:
            form = self.form_class()
            return render(request, self.template_name, context={'form': form,})
    
    def post(self, request, *args, **kwargs):
        response = self.response_fn(request)

        if response.status_code == 200:
            request.session['id'] = json.loads(response.content.decode('utf-8'))['id']
            request.session['qrcodeB64'] = json.loads(response.content.decode('utf-8'))['qrcodeB64']
            return redirect(request.path)
        elif response.status_code == 302:
            return redirect(response.url)
        else:
            return HttpResponse(status=500)


class RegisterView(InputView):
    form_class = RegistrationSessionForm
    template_name = 'webapp/register.html'
    response_fn = registerMiddlewareView


class RegisterBiometricsView(TemplateView):
    template_name = 'webapp/register_biometrics.html'


class LoginView(InputView):
    form_class = LoginForm
    template_name = 'webapp/login.html'
    response_fn = loginMiddlewareView


class LoginBiometricsView(TemplateView):
    template_name = 'webapp/login_biometrics.html'
