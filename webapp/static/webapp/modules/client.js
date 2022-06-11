import { WebAuthnHelpers } from "./WebAuthnHelpers.js";

const registerCredential = async (options) => {
    // convert fields WebAuthn expects as ArrayBuffer
    options.challenge = WebAuthnHelpers.coerceToArrayBuffer(options.challenge);
    options.user.id = WebAuthnHelpers.coerceToArrayBuffer(options.user.id);
    options.excludeCredentials = options.excludeCredentials.map((c) => {
        c.id = WebAuthnHelpers.coerceToArrayBuffer(c.id);
        return c;
    });
    const cred = await navigator.credentials.create({
        publicKey: options
    });

    const credential = {};
    credential.id = cred.id;
    credential.rawId = WebAuthnHelpers.coerceToBase64Url(cred.rawId);
    credential.type = cred.type;

    if (cred.response) {
        const clientDataJSON =
            WebAuthnHelpers.coerceToBase64Url(cred.response.clientDataJSON);
        const attestationObject =
            WebAuthnHelpers.coerceToBase64Url(cred.response.attestationObject);
        credential.response = {
            clientDataJSON,
            attestationObject
        };
    }

    return credential;
}

export { registerCredential };