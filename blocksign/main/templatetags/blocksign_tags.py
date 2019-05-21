import datetime

from django import template

register = template.Library()

@register.filter
def get_timestamp(datetime_obj):
    try:
        return int(datetime_obj.timestamp())
    except:
        return None
