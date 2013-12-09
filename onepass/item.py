class BaseItem(object):
    def __init__(self, meta, data):
        self._meta = meta
        self._data = data

    @property
    def metadata(self):
        return self._meta

    @property
    def data(self):
        return self._data

    @property
    def type(self):
        return self._meta['typeName']

    @property
    def title(self):
        return self._meta['title']

    @property
    def notes(self):
        return self._data.get('notesPlain')

    @classmethod
    def create(klass, meta, data):
        ty = meta.get('typeName')
        # TODO: pick what class to instantiate (maybe using prefix tree?)


class WebItem(BaseItem):
    @property
    def username(self):
        for f in self._data['fields']:
            if f.get('designation', '') == 'username':
                return f['value']

        return None

    @property
    def password(self):
        for f in self._data['fields']:
            if f.get('designation', '') == 'password':
                return f['value']

        return None
