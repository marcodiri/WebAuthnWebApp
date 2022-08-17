import json
import logging

from django.http import HttpResponse
from django.views.generic import TemplateView
from django.contrib import messages
from django.shortcuts import render, redirect

from authenticator.forms import LoginForm, TempSessionForm
from authenticator.views import loginMiddlewareView, registerMiddlewareView

logger = logging.getLogger('webapp.logger')

class LoginView(TemplateView):
    form_class = LoginForm
    template_name = 'webapp/login.html'
    
    def get(self, request, *args, **kwargs):
        form = self.form_class()
        return render(request, self.template_name, context={'form': form,})
    
    def post(self, request, *args, **kwargs):
        response = loginMiddlewareView(request)

        if response.status_code == 200:
            request.session['session_id'] = json.loads(response.content.decode('utf-8'))['session_id']
            request.session['qrcodeB64'] = json.loads(response.content.decode('utf-8'))['qrcodeB64']
            return redirect(request.path)
        elif response.status_code == 302:
            return redirect(response.url)
        else:
            return HttpResponse(status=500)

class RegisterView(TemplateView):
    form_class = TempSessionForm
    template_name = 'webapp/register.html'

    def get(self, request, *args, **kwargs):
        if 'session_id' in request.session:
            session_id = request.session['session_id']
            qrcodeB64 = request.session['qrcodeB64']
            del request.session['session_id']
            del request.session['qrcodeB64']
            context = {
                'session_id': session_id,
                'qrcodeB64': qrcodeB64,
            }
            return render(request, self.template_name, context=context)
        else:
            form = self.form_class()
            return render(request, self.template_name, context={'form': form,})
    
    def post(self, request, *args, **kwargs):
        response = registerMiddlewareView(request)

        if response.status_code == 200:
            request.session['session_id'] = json.loads(response.content.decode('utf-8'))['session_id']
            request.session['qrcodeB64'] = json.loads(response.content.decode('utf-8'))['qrcodeB64']
            return redirect(request.path)
        elif response.status_code == 302:
            return redirect(response.url)
        else:
            return HttpResponse(status=500)


class RegisterBiometricsView(TemplateView):
    template_name = 'webapp/register_biometrics.html'

