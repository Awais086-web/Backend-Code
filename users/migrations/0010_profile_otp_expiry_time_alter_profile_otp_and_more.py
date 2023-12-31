# Generated by Django 4.1.2 on 2023-06-20 00:23

from django.db import migrations, models
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ("users", "0009_otpprofile"),
    ]

    operations = [
        migrations.AddField(
            model_name="profile",
            name="otp_expiry_time",
            field=models.DateTimeField(default=django.utils.timezone.now),
        ),
        migrations.AlterField(
            model_name="profile",
            name="otp",
            field=models.CharField(max_length=6),
        ),
        migrations.DeleteModel(
            name="otpProfile",
        ),
    ]
