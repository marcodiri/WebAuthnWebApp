import uuid
from django import forms
from .models import TempSession

# class TempSessionForm(forms.ModelForm):
#     class Meta:
#         model = TempSession
#         exclude = ['id']
#         widgets = {
#             'password': forms.PasswordInput(),
#         }


class TempSessionForm(forms.ModelForm):
    username = forms.RegexField(
        max_length=10, regex=r'^[\w.@+-]+$',
        error_messages = {'invalid': "Username may be max 10 characters and may contain only letters, numbers and @/./+/-/_."}
    )
    password = forms.CharField(label='Password', widget=forms.PasswordInput)

    class Meta:
        model = TempSession
        fields = ('username',)

    def clean_username(self):
        username = self.cleaned_data['username'].strip()
        try:
            TempSession.objects.get(username__iexact=username)
            raise forms.ValidationError('Username already exists')
        except TempSession.DoesNotExist:
            return username

    def save(self, commit=True):
        temp_session = super().save(commit=False)
        # set an uuid for the temporary session
        temp_session.id = uuid.uuid4()
        # save the provided password in hashed format
        temp_session.set_password(self.cleaned_data["password"])
        if commit:
            temp_session.save()
        return temp_session
