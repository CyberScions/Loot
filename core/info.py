#!/usr/bin/env python
# -*- coding: utf-8 -*-
# -*- coding: binary -*-

from core.libs.colors import paint

class notifications(object):

    INFO = paint.W+"[FOUND]"+paint.N+": "
    FAIL = paint.R+"[FAILED]"+paint.N+": "
    STATUS = paint.Y+"[RESULTS]"+paint.N+": "
