FROM python:alpine

RUN apk add git && git clone https://github.com/marcodiri/webauthn_biometric_authentication.git /webauthn

WORKDIR /webauthn

RUN pip install pipenv
RUN export PIPENV_VENV_IN_PROJECT=1 && pipenv install

ARG HOSTNAME
ENV HOSTNAME=${HOSTNAME:-localhost}
RUN printf 'SECRET_KEY=foo\nHOSTNAME=%s\nRP_NAME="WebAuthn WebApp"' $HOSTNAME > webauthn_webapp/.env \
&& echo created .env: && cat webauthn_webapp/.env

RUN .venv/bin/python manage.py makemigrations authenticator && \
.venv/bin/python manage.py migrate

ENTRYPOINT [".venv/bin/python", "manage.py", "runsslserver"]
CMD ["0.0.0.0:8000"]

EXPOSE 8000