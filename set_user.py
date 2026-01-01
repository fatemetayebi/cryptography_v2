class AppConfig:
    def __init__(self):
        self._username = None
        self._password = None

    @property
    def username(self):
        return self._username

    @property
    def password(self):
        return self._password

    def set_credentials(self, username, password):
        self._username = username
        self._password = password


app_config = AppConfig()