import django_filters

from .enums import ROLE_CHOICE
from .models import User


class UserFilter(django_filters.FilterSet):
    role = django_filters.MultipleChoiceFilter(choices=ROLE_CHOICE,method='filter_role')
    
    class Meta:
        model = User
        fields = ['role','verified']

    def filter_role(self, queryset, name, value):
        return queryset.filter(roles__name__in=value).distinct()