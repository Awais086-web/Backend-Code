# Generated by Django 4.1.2 on 2023-06-19 10:23

import ckeditor.fields
from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("users", "0003_privacypolicy"),
    ]

    operations = [
        migrations.AlterField(
            model_name="privacypolicy",
            name="content",
            field=ckeditor.fields.RichTextField(),
        ),
        migrations.AlterField(
            model_name="termsandconditions",
            name="content",
            field=ckeditor.fields.RichTextField(),
        ),
    ]
