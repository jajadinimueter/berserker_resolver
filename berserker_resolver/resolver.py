# -*- coding: utf-8 -*-
from itertools import chain

from dns.resolver import Resolver
from berserker_resolver.compat import xrange_compat
from berserker_resolver.base import set_kwargs, fold
from berserker_resolver.concurrence import ThreadConcurrence
from berserker_resolver.mixins import WwwMixin

class SimpleResolver(object):
    tries = 2
    lifetime = 1
    nameservers = ['8.8.8.8', '8.8.4.4',]
    resolver_backend = Resolver()

    def __init__(self, **kwargs):
        kwargs = set_kwargs(self, kwargs, ['tries', 'nameservers', 'lifetime'])
        self.resolver_backend.lifetime = self.lifetime
        super(SimpleResolver, self).__init__(**kwargs)

    def query(self, to_resolve, rdtypes=None):
        '''
        Performs query to the backend.

        :param to_resolve: List domains to resolve.

        Exmaple:
        to_resolve = [
            dict(domain='xxx.com', nameserver='8.8.8.8'),
            dict(domain='abc.com', nameserver='4.2.2.1')
        ]
        '''
        rdtypes = rdtypes or ['A']

        ns = to_resolve['nameserver']
        domain = to_resolve['domain']
        result = []
        try:
            self.resolver_backend.nameservers = [ns]
            if len(rdtypes) == 1:
                result = list(self.resolver_backend.query(domain, rdtypes.pop()))
            else:
                result = list(chain(*[list(self.resolver_backend.query(domain, rdtype))
                                     for rdtype in rdtypes]))
        except:
            pass

        return dict(
            domain=domain,
            nameserver=ns,
            result=result
        )

    def attach_tries_and_nameservers(self, domains):
        attached = []
        for d in domains:
            for t in xrange_compat(self.tries):
                for ns in self.nameservers:
                    attached.append(dict(nameserver=ns, domain=d))
        return attached

    def resolve_middleware(self, to_resolve, **query_args):
        resolved = []
        for i in to_resolve:
            resolved.append(self.query(i, **query_args))
        return resolved

    def resolve(self, domains, **query_args):
        '''
        Resolves domains.

        Firstly attaches tries and nameservers, secondly does resolve with resolve_middleware,
        thirdly folds results.
        '''
        if not isinstance(domains, list):
            raise TypeError('Domains must be in list, example: [\'google.com\', \'test.net\']')

        if len(domains) == 0:
            return None

        to_resolve = self.attach_tries_and_nameservers(domains)
        resolved = self.resolve_middleware(to_resolve, **query_args)
        resolved = fold((i['domain'], i['result']) for i in resolved)
        return resolved

class ThreadResolver(WwwMixin, SimpleResolver, ThreadConcurrence):
    def __init__(self, **kwargs):
        super(ThreadResolver, self).__init__(**kwargs)

    def resolve_middleware(self, to_resolve, **query_args):
        return self.thread_resolve(to_resolve, **query_args)
