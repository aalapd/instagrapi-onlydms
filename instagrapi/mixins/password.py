import time

class PasswordMixin:
    def password_encrypt(self, password):
        """
        Encrypt the given password by sending a request to the local encryption service.

        The service is expected to receive a JSON payload with:
          - password: the plain-text password,
          - publickeyid: the public key identifier,
          - publickey: a valid Base64‑encoded RSA public key,
          - timestamp: the current timestamp (as a string).

        It should return a JSON response containing the encrypted password.
        """
        # Retrieve the public key ID and the Base64‑encoded public key from Instagram.
        publickeyid, publickey = self.password_publickeys()
        timestamp = str(int(time.time()))
        
        # Prepare the payload for the encryption service.
        payload = {
            "password": password,
            "publickeyid": publickeyid,
            "publickey": publickey,
            "timestamp": timestamp
        }
        
        # Send a POST request to the encryption service.
        response = self.public.post("http://127.0.0.1:8000/encrypt", json=payload)
        data = response.json()
        
        # If the service returned an error, raise an exception.
        if response.status_code != 200:
            raise Exception("Encryption service error: " + data.get("detail", "unknown error"))
        
        # Return the encrypted password from the service response.
        return data["encrypted_password"]

    def password_publickeys(self):
        """
        Retrieve Instagram's public key information by making a GET request to Instagram's endpoint.

        Expects the response headers to contain:
          - 'ig-set-password-encryption-key-id': the public key ID.
          - 'ig-set-password-encryption-pub-key': the Base64‑encoded public key.
        """
        resp = self.public.get("https://i.instagram.com/api/v1/qe/sync/")
        publickeyid = int(resp.headers.get("ig-set-password-encryption-key-id"))
        publickey = resp.headers.get("ig-set-password-encryption-pub-key")
        return publickeyid, publickey
