import datetime


class Session:
    def __init__(self):
        self.flask = wiz.server.package.flask
    
    def has(self, key):
        if key in self.flask.session:
            return True
        return False
    
    def delete(self, key):
        self.flask.session.pop(key, None)
    
    def set(self, **kwargs):
        for key in kwargs:
            self.flask.session[key] = kwargs[key]
    
    def get(self, key=None, default=None):
        if key is None:
            return self.to_dict()
        if key in self.flask.session:
            return self.flask.session[key]
        return default

    def clear(self):
        self.flask.session.clear()

    def age_seconds(self, timestamp_key, now=None):
        value = self.get(timestamp_key, None)
        if value in [None, ""]:
            return None
        if isinstance(value, str):
            try:
                value = datetime.datetime.fromisoformat(value)
            except (TypeError, ValueError):
                return None
        if not isinstance(value, datetime.datetime):
            return None

        if value.tzinfo is not None:
            value = value.astimezone(datetime.timezone.utc)
            current = now or datetime.datetime.now(datetime.timezone.utc)
            if current.tzinfo is None:
                current = current.replace(tzinfo=datetime.timezone.utc)
            else:
                current = current.astimezone(datetime.timezone.utc)
        else:
            current = now or datetime.datetime.now()
            if current.tzinfo is not None:
                current = current.astimezone(datetime.timezone.utc).replace(tzinfo=None)
        return max(0, (current - value).total_seconds())

    def is_expired(self, timestamp_key, ttl_seconds, now=None):
        value = self.get(timestamp_key, None)
        if value in [None, ""]:
            return False
        age = self.age_seconds(timestamp_key, now=now)
        if age is None:
            return True
        try:
            ttl_seconds = int(ttl_seconds)
        except (TypeError, ValueError):
            return True
        return ttl_seconds <= 0 or age >= ttl_seconds

    def to_dict(self):
        return season.util.stdClass(dict(self.flask.session))

    def user_id(self):
        config = wiz.model("portal/season/config")
        session_user_id = config.session_user_id
        return session_user_id()
    
    def create(self, key):
        config = wiz.model("portal/season/config")
        config.session_create(wiz, key)

    @classmethod
    def use(cls):
        return cls()

Model = Session()
