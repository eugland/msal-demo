#!/usr/bin/env python
# Copyright (C) Microsoft Corporation. All rights reserved.

"""Classes and functions meant to assist in interacting with the Auth API"""

import logging
import msal
import os
import time
import traceback

from azure.core.credentials import AccessToken

LOG_LEVEL_STATUS = logging.INFO + 1

class MSALTokenAuthenticationClient(object):
    """A representation of the client with token authentication mechanism"""

    def __init__(self, service_name, authority_uri, client_id=None, resource_id=None):
        self.service_name = service_name
        self.authority_uri = authority_uri
        self.client_id = client_id
        self.resource_id = resource_id
        self.auth_file = os.path.join('~', '.config', 'EdgeAuthCache', self.service_name, 'token_cache.json')
        self.token_cache_file = os.path.expanduser(self.auth_file)
        self.token_cache = msal.SerializableTokenCache()
        self.app = msal.PublicClientApplication(self.client_id, authority=self.authority_uri, token_cache=self.token_cache)
        self.access_token_full = None

    def authenticate(self, try_device_login=True):
        # We need a scope, due to the use of MSAL, which is build on using
        # Microsoft Identity Platform v2 (MIPv2) APIs, which moved to send
        # scopes instead of resource ids. The best way to convert resource
        # ids to be scopes is to suffix them with "/.default", which means
        # that they should get the scopes defined in the local AAD app for
        # the targeted resource.
        # Resource identifiers here will be in one of two forms:
        # 1) The first form is a resource value, which is a URI, e.g.
        #      https://graph.microsoft.com
        #    This is turned into a scope by appending "/.default":
        #      https://graph.microsoft.com/.default
        # 2) The second form is a resource id, which is a GUID, e.g.
        #      XXXXXXXX-XXXX-XXXX-XXXXXXXXXXXX
        #    This is similarly canonicalized as
        #      XXXXXXXX-XXXX-XXXX-XXXXXXXXXXXX/.default
        #    The similarity is purely for ease of implementation.
        # Documentation on this quirk can be found at
        # https://docs.microsoft.com/en-us/azure/active-directory/develop/migrate-adal-msal-java

        # remove any whitespace and trailing slashes
        scope = self.resource_id.strip().rstrip('/')

        # handle user code providing scopes even though the api says to use
        # resources; only works for the .default scope specifier, but it is
        # by far the most common to use (and is recommended by AAD docs).
        if not scope.endswith('/.default'):
            scope = scope + '/.default'

        self.access_token_full = self._get_access_token([scope], try_device_login)
        return self.access_token

    @property
    def access_token(self):
        """ Retrieve the 'access_token' property from the full JWT Access Token.
        """
        if self.access_token_full:
            return self.access_token_full['access_token']
        return None

    def get_token(self, *scopes, **_kwargs):
        try:
            token = self._get_access_token(list(scopes), True)
            if token:
                return AccessToken(token['access_token'], time.time() + token['expires_in'])
        except:
            traceback.print_exc()
            raise
        return None

    def _get_access_token(self, scopes, try_device_login):
        token = self._get_token_from_cache(scopes)

        logging.debug('msal_token_authentication_client::_get_access_token(): (token == None)= %s, (\'access_token\' in token) = %s',
                      str(token == None), str(token != None and 'access_token' in token))

        if token is None and try_device_login:
            token = self._get_token_with_device_login(scopes)
            self._save_cache()

        return token

    def _load_cache(self):
        if (os.path.isfile(self.token_cache_file)):
            try:
                with open(self.token_cache_file, 'r+') as cache_file:
                    logging.debug('Deserializing token cache file from path %s', self.token_cache_file)
                    self.token_cache.deserialize(cache_file.read())
            except Exception:
                logging.exception('Failed to load token cache file')
                self._delete_cache()

    def _save_cache(self):
        try:
            dirname = os.path.dirname(self.token_cache_file)
            if not os.path.exists(dirname):
                os.makedirs(dirname)
            with open(self.token_cache_file, 'w') as cache_file:
                cache_file.write(self.token_cache.serialize())
        except Exception:
            logging.exception('Failed to save token cache')

    def _delete_cache(self):
        if (os.path.isfile(self.token_cache_file)):
            logging.log(LOG_LEVEL_STATUS, 'Deleting token cache file %s', self.token_cache_file)
            os.remove(self.token_cache_file)

    def _get_token_from_cache(self, scopes):
        self._load_cache()
        try:
            accounts = self.app.get_accounts()
            dbg_message = 'accounts == None' if accounts == None else 'len(accounts) = %d' %(len(accounts))
            logging.debug(dbg_message)
            if accounts and len(accounts) > 0:
                if len(accounts) > 1:
                    logging.warn('Found multiple cached accounts, using %s', accounts[0])
                account = accounts[0]
                logging.debug('self.apap.calling acquire_token_silent')
                return self.app.acquire_token_silent(scopes, account=account)
        except Exception:
            #delete cache file first, in event we throw printing the exception message (which has happened)
            self._delete_cache()
            logging.exception('Error acquiring auth context')
        return None

    def _get_token_with_device_login(self, scopes):
        flow = self.app.initiate_device_flow(scopes=scopes)
        if 'message' in flow:
            print(flow['message'])
        token = self.app.acquire_token_by_device_flow(flow)
        return token
