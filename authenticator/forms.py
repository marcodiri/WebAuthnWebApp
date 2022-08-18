import uuid
from django import forms
from .models import RegistrationSession, User


class RegistrationSessionForm(forms.ModelForm):
    username = forms.RegexField(
        max_length=10, regex=r'^[\w.@+-]+$',
        error_messages = {'invalid': "Username may be max 10 characters and may contain only letters, numbers and @/./+/-/_."}
    )
    password = forms.CharField(label='Password', widget=forms.PasswordInput)

    class Meta:
        model = RegistrationSession
        fields = ('username',)

    def clean_username(self):
        username = self.cleaned_data['username'].strip()
        try:
            RegistrationSession.objects.get(username__iexact=username)
            raise forms.ValidationError('Username already exists')
        except RegistrationSession.DoesNotExist:
            return username

    def save(self, commit=True):
        registration_session = super().save(commit=False)
        # set an uuid for the temporary session
        registration_session.id = uuid.uuid4()
        # save the provided password in hashed format
        registration_session.set_password(self.cleaned_data["password"])
        if commit:
            registration_session.save()
        return registration_session


class LoginForm(forms.Form):
    username = forms.RegexField(
        max_length=10, regex=r'^[\w.@+-]+$',
        error_messages = {'invalid': "Username may be max 10 characters and may contain only letters, numbers and @/./+/-/_."}
    )
    
    class Meta:
        model = User
        fields = ('username',)

    def clean_username(self):
        username = self.cleaned_data['username'].strip()
        try:
            User.objects.get(username__iexact=username)
            return username
        except User.DoesNotExist:
            raise forms.ValidationError('Username does not exist')
