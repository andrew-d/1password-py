import json
from collections import MutableMapping


class BaseItem(object):
    def __init__(self, meta, data):
        self._meta = meta
        self._data = json.loads(data)

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

    @property
    def default(delf):
        """
        Override this to provide a default value to be shown to the user - for
        example, a form's password field, a credit card's card number, or a
        note's text.
        """
        return ''

    @classmethod
    def create(klass, meta, data):
        cls = _CLASS_MAP.get_closest(meta['typeName'])
        return cls(meta, data)


class WebItem(BaseItem):
    @property
    def username(self):
        for f in self._data['fields']:
          if f.get('designation', '') == 'username':
                return f['value']

        return None

    @property
    def password(self):
        # Find the designated 'password' field.
        for f in self._data['fields']:
            if f.get('designation', '') == 'password':
                return f['value']

        # Fallback to finding anything with the name 'password'
        for f in self._data['fields']:
            if f.get('name', '').lower() == 'password':
                return f['value']

        return None

    @property
    def location(self):
        return self._meta['locationKey']

    @property
    def default(self):
        # Overridden default display
        return self.password


class NoteItem(BaseItem):
    @property
    def default(self):
        # Overridden default display
        return self.notes


class PrefixLookup(object):
    def __init__(self):
        self._mapping = {}

    def _get_node(self, path, create=False):
        curr = self._mapping
        for node in path:
            if node in curr:
                curr = curr[node]
            elif create:
                curr[node] = {}
                curr = curr[node]
            else:
                raise KeyError(path)

        return curr

    def map(self, path, klass):
        path = path.split('.')
        curr = self._get_node(path[:-1], create=True)
        curr[path[-1]] = klass

    def __getitem__(self, key):
        path = key.split('.')
        curr = self._get_node(path[:-1])
        return curr[path[-1]]

    def get_closest(self, key):
        # Last found item
        last = None

        # Current node
        curr = self._mapping

        # Walk through all items, saving any blank items as the 'last found'
        # item.
        path = key.split('.')
        for node in path[:-1]:
            if '' in curr:
                last = curr['']

            if node in curr:
                curr = curr[node]

        # If we have an exact match, use that, else just use the last item.
        if path[-1] in curr:
            last = curr[path[-1]]

        return last


# From the test data:
# types = set([x.metadata.get('typeName', '') for x in k.items])
#   set([u'wallet.financial.CreditCard', u'system.Tombstone',
#        u'wallet.computer.License', u'wallet.onlineservices.ISP',
#        u'wallet.computer.Database', u'webforms.WebForm',
#        u'wallet.onlineservices.InstantMessenger',
#        u'wallet.membership.Membership', u'wallet.government.SsnUS',
#        u'passwords.Password', u'wallet.onlineservices.GenericAccount',
#        u'securenotes.SecureNote', u'wallet.government.DriversLicense',
#        u'wallet.computer.UnixServer', u'identities.Identity',
#        u'wallet.onlineservices.AmazonS3', u'system.folder.Regular',
#        u'wallet.financial.BankAccountUS'])

_CLASS_MAP = PrefixLookup()
_CLASS_MAP.map('', BaseItem)
_CLASS_MAP.map('webforms.WebForm', WebItem)
_CLASS_MAP.map('securenotes.SecureNote', NoteItem)
