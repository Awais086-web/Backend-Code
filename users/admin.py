from django.contrib import admin
from django.db import models
from django.conf import settings
from django.db import models
from ckeditor.widgets import CKEditorWidget
from .models import TermsAndConditions
from .models import Profile
from .models import PrivacyPolicy

admin.site.register(Profile)




# this is for update the html pages
class MyCKEditorWidget(CKEditorWidget):
    def render(self, name, value, attrs=None, renderer=None):
        if value is None:
            value = ''
        rendered = super().render(name, value, attrs, renderer)
        rendered += f'<script type="text/javascript">CKEDITOR.config["filebrowserBrowseUrl"] = "{settings.STATIC_URL}ckeditor/ckeditor/config.js";</script>'
        return rendered

class TermsAndConditionsAdmin(admin.ModelAdmin):
    formfield_overrides = {
        models.TextField: {'widget': MyCKEditorWidget},
    }

admin.site.register(TermsAndConditions, TermsAndConditionsAdmin)


class PrivacyPolicyAdmin(admin.ModelAdmin):
    formfield_overrides = {
        models.TextField: {'widget': MyCKEditorWidget},
    }

admin.site.register(PrivacyPolicy, PrivacyPolicyAdmin)