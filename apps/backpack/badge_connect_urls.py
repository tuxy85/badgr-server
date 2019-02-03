# encoding: utf-8
from __future__ import unicode_literals

from django.conf.urls import url

from backpack.api import BackpackAssertionList
from mainsite.badge_connect_api import BadgeConnectProfileView

urlpatterns = [
    url(r'^assertions$', BackpackAssertionList.as_view(), name='bc_api_backpack_assertion_list'),
    url(r'^profile$', BadgeConnectProfileView.as_view(), name='bc_api_profile'),
]