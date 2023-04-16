# Generated by Django 4.0.6 on 2023-03-31 05:34

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0009_alter_talentinfo_job_title_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='talentinfo',
            name='migration_test_field',
            field=models.BooleanField(default=False),
        ),
        migrations.AlterField(
            model_name='talentinfo',
            name='job_title',
            field=models.CharField(max_length=100),
        ),
        migrations.AlterField(
            model_name='talentinfo',
            name='level_of_education',
            field=models.CharField(max_length=100),
        ),
        migrations.AlterField(
            model_name='talentinfo',
            name='years_of_experience',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
    ]