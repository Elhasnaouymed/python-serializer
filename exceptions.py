class SerializerException(Exception):
    message = "Serializer Error."

    def __init__(self, message=None):
        if message is not None:
            self.message = message
        super(SerializerException, self).__init__(self.message)


class SerializerTokenExpired(SerializerException):
    message = 'Token Expired!'


class SerializerTokenCorrupt(SerializerException):
    message = 'Token Has been tampered with!'


class SerializerNotInitialized(SerializerException):
    message = 'Serializer has not been initialized!'


class SerializerAlreadyInitialized(SerializerException):
    message = 'Serializer has already been initialized!'
