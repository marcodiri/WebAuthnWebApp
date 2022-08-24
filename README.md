# WebAuthn for biometric authentication
## Run
As per [Webauthn specification](https://w3c.github.io/webauthn/#relying-party-identifier), the host's domain name (i.e. the address you visit to open the website) cannot be an IP address (see [issue](https://github.com/w3c/webauthn/issues/1358)).<br>
This means that when testing locally, you cannot connect to the webserver through the IP of the host machine, otherwise Webauthn will fail to verify the client.
Instead you'll have to connect through the host **network name**, which usually modems automatically set to the connected machine **hostname**.<br>
If that is not the case, you'll have to go to your modem page and add a DNS entry to redirect an *hostname* of your choice to the host machine IP address.

### Docker
1. Download the [Dockerfile](https://raw.githubusercontent.com/marcodiri/WebAuthnWebApp/master/Dockerfile)
2. Print hostname and verify that the host machine is reachable:
   ```bash
   Linux:
   $ hostname
   $ ping `hostname`
   
   Windows (cmd):
   > echo %COMPUTERNAME%
   > ping %COMPUTERNAME%
   ```
   If ping fails, add a DNS entry as stated above and ping your custom entry to make sure it works.
3. Open a terminal in the Dockerfile directory and run:
   ```bash
   Linux:
   $ docker build -t sekm:webauthn --build-arg HOSTNAME=`hostname` .
   $ docker run --rm -it -p 8000:8000 sekm:webauthn
   
   Windows (cmd):
   > docker build -t sekm:webauthn --build-arg HOSTNAME=%COMPUTERNAME% .
   > docker run --rm -it -p 8000:8000 sekm:webauthn
   ```
   The above commands will make the server reachable via the *hostname*. If you made a custom DNS entry you should set the HOSTNAME accordingly.
4. Connect to `https://hostname:8000`, *hostname* is the one found on step 2 or the one you set in the DNS entry.
   As per Webauthn specification, only *https* is allowed, but since no certificates are available when local testing, the browser will display a warning, tell it to proceed anyway.

## Usage
Your desktop and mobile devices have to be on the same network.
### Register with fingerprint
1. Connect to the webserver from **desktop**
2. Click **Register**
3. Choose *Username* and *Password*
4. A QR code containing a link will be generated, leave this page open
5. Scan the QR on a **mobile device with biometric sensor available**
6. A webpage will open asking you to repeat the password chosen at step 2 and click *Proceed*
7. The device will ask you to scan your fingerprint
8. After that the account will be created
9. After a short while, the desktop will be redirected to a *success* page.

### Login with fingerprint
1. Connect to the webserver from **desktop**
2. Click **Login**
3. Insert a registered *Username*
4. A QR code containing a link will be generated, leave this page open
5. Scan the QR on a **mobile device with biometric sensor available**
6. A webpage will open and check if the biometric sensor is the one associated with the *User*
7. If positive, the device will ask you to scan your fingerprint
8. After a short while, the desktop will be redirected to the *User Profile* page.