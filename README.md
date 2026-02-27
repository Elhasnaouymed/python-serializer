# Serializer

This is a Wrapper Python class that helps to serialize and deserialize Python data with many options, like timestamping the data,
encrypting it with AES-GCM or signing it using HMAC.  
This class also have two methods to hash passwords / verify them using bcrypt library.

## Example

You want to send email verification token to the user `#1` with email `user1@example.com`:

First Initialize the Serializer:

```python
YOUR_APP_SECRET_KEY = '20a0c09281f74f459128bcf9f2cb01eb3244991140bfe903f28cd9752f33275f'
serializer = Serializer(YOUR_APP_SECRET_KEY)
```

Then make a list with the info of that user **(any jsonable type is supported)**:

```python
email_verification_info = [1, 'user1@example.com']
```

And then use the method `serialize` to turn it into a URL-Safe token:

```python
token = serializer.serialize(email_verification_info)
print(token)

# > YVlJRN3_SpIJ9EW0biJ36m-UMk4gDLWbfNnHaIGp5DFq87-yJBb9-6vi1xmKOIT1JBa_P-WFAvRUCLRkSoi4gZeuuj6a5fwqDTz6mxQ=
```

Now you have a token that is timestamped, encrypted and url-safe.

when the user clicks on the link, and you retrieve the token, all you have to do to get the original data is:

```python
original_info = serializer.deserialize(token)
print(original_info)

# > [1, 'user1@example.com']
```

> AES-GCM is used by default to encrypt / tag the token using provided secret key in this example `YOUR_APP_SECRET_KEY`, you obviously should choose different key and DO NOT LOSE IT.

## HMAC instead of AES

if you don't care about confidentiality, and want more efficiency, you can use HMAC instead:

```python
token = serializer.serialize(email_verification_info, hmac=True)
print(token)

# > aJf2x_gcSqNZoAhzVwYNbQKcvI0Rx5mOQRYKrg8nIKFpAAAAAFsxLCAidXNlcjFAZXhhbXBsZS5jb20iXQ==
```

## Checking Expiration

Tokens are timestamped by default, so all you have to do to check if they are expired or not is to give expiration period is seconds:

```python
original_info = serializer.deserialize(token, expiration_seconds=3600)

Traceback (most recent call last):
  File "./main.py", line 19, in <module>
    original_info = serializer.deserialize(token, expiration_seconds=1)
  File "./serializer/__init__.py", line 186, in deserialize
    raise errors.SerializerTokenExpired()
serializer.exceptions.SerializerTokenExpired: Token Expired!
```

---

## Other Methods

You also have these other methods to use:

- Encrypt and Decrypt using AES-GCM
  - `encrypt(plaintext: bytes) -> bytes`
  - `decrypt(data: bytes) -> bytes`
- Sign using HMAC and verify
  - `hmac_sign(text: bytes) -> bytes` _(only returns the signature)_
  - `hmac_verify(text: bytes, signature: bytes) -> bool`
- Hash Passwords and verify them
  - `hash_password(password: str) -> str`
  - `verify_password(password: str, hashed: str) -> bool`

---

> Keep in mind that you should always provide the same secret key you initialized the instance with, unless you know what you are doing. 