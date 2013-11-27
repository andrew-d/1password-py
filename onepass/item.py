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
