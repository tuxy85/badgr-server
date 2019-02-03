# encoding: utf-8
from __future__ import unicode_literals

from rest_framework import serializers
from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework.exceptions import ValidationError as RestframeworkValidationError

from entity.serializers import DetailSerializerV2
from issuer.helpers import BadgeCheckHelper
from issuer.models import BadgeInstance
from issuer.serializers_v2 import BadgeRecipientSerializerV2, EvidenceItemSerializerV2
from mainsite.serializers import MarkdownCharField, HumanReadableBooleanField


class BaseSerializerBC(serializers.Serializer):
    _success = True
    _description = "ok"

    @property
    def success(self):
        return self._success

    @success.setter
    def success(self, value):
        self._success = value

    @property
    def description(self):
        return self._description

    @description.setter
    def description(self, value):
        self._description = value

    def __init__(self, *args, **kwargs):
        self.success = kwargs.pop('success', True)
        self.description = kwargs.pop('description', 'ok')
        super(BaseSerializerBC, self).__init__(*args, **kwargs)

    @staticmethod
    def response_envelope(result, success, description, field_errors=None, validation_errors=None):
        # assert isinstance(result, collections.Sequence)

        envelope = {
            "status": {
                "statusCode": 200,
                "statusText": description,
                "error": None
            },
            "results": result
        }

        if field_errors is not None:
            envelope["fieldErrors"] = field_errors

        if validation_errors is not None:
            envelope["validationErrors"] = validation_errors

        return envelope


class BackpackAssertionSerializerBC(BaseSerializerBC):
    id = serializers.URLField(source='jsonld_id', read_only=True)
    badge = serializers.URLField(source='badgeclass_jsonld_id', read_only=True)
    image = serializers.FileField(read_only=True)
    recipient = BadgeRecipientSerializerV2(source='*')
    issuedOn = serializers.DateTimeField(source='issued_on', read_only=True)
    narrative = MarkdownCharField(required=False)
    evidence = EvidenceItemSerializerV2(many=True, required=False)
    revoked = HumanReadableBooleanField(read_only=True)
    revocationReason = serializers.CharField(source='revocation_reason', read_only=True)
    expires = serializers.DateTimeField(source='expires_at', required=False)

    class Meta(DetailSerializerV2.Meta):
        model = BadgeInstance

    def to_representation(self, instance):
        representation = super(BackpackAssertionSerializerBC, self).to_representation(instance)
        representation['@context'] = 'https://w3id.org/openbadges/v2'
        request_kwargs = self.context['kwargs']
        expands = request_kwargs.get('expands', [])

        if self.parent is not None:
            # we'll have a bare representation
            instance_data_pointer = representation
        else:
            instance_data_pointer = representation['results'][0]

        if 'badgeclass' in expands:
            instance_data_pointer['badge'] = instance.cached_badgeclass.get_json(include_extra=True, use_canonical_id=True)
            if 'issuer' in expands:
                instance_data_pointer['badge']['issuer'] = instance.cached_issuer.get_json(include_extra=True, use_canonical_id=True)

        return representation


class BackpackImportSerializerBC(BaseSerializerBC):
    id = serializers.URLField()  # This will only work for hosted assertions for now

    def create(self, validated_data):
        url = validated_data['id']
        try:
            instance, created = BadgeCheckHelper.get_or_create_assertion(url=url, created_by=self.context['request'].user)
            if not created:
                instance.acceptance = BadgeInstance.ACCEPTANCE_ACCEPTED
                instance.save()
                raise RestframeworkValidationError([{'name': "DUPLICATE_BADGE", 'description': "You already have this badge in your backpack"}])
        except DjangoValidationError as e:
            raise RestframeworkValidationError(e.messages)
        return instance


class ProfileSerializerBC(BaseSerializerBC):
    name = serializers.CharField(read_only=True, source='first_name')
    email = serializers.EmailField(read_only=True)

    def to_representation(self, instance):
        representation = super(ProfileSerializerBC, self).to_representation(instance)
        representation['@context'] = 'https://w3id.org/openbadges/v2'
        return representation
