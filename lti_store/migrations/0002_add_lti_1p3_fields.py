# Generated by Django 3.2.17 on 2023-09-27 04:41

from django.db import migrations, models
import lti_store.models


class Migration(migrations.Migration):

    dependencies = [
        ('lti_store', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='externallticonfiguration',
            name='lti_1p3_client_id',
            field=models.CharField(blank=True, help_text='Client ID used by LTI tool', max_length=255, verbose_name='LTI 1.3 Client ID'),
        ),
        migrations.AddField(
            model_name='externallticonfiguration',
            name='lti_1p3_deployment_id',
            field=models.CharField(blank=True, help_text='Deployment ID used by LTI tool', max_length=255, verbose_name='LTI 1.3 Deployment ID'),
        ),
        migrations.AddField(
            model_name='externallticonfiguration',
            name='lti_1p3_launch_url',
            field=models.URLField(blank=True, help_text='This is the LTI launch URL, otherwise known as the target_link_uri.\n        It represents the LTI resource to launch to or load in the second leg of the launch flow,\n        when the resource is actually launched or loaded.', max_length=255, verbose_name='LTI 1.3 Launch URL'),
        ),
        migrations.AddField(
            model_name='externallticonfiguration',
            name='lti_1p3_oidc_url',
            field=models.URLField(blank=True, help_text='This is the OIDC third-party initiated login endpoint URL in the LTI 1.3 flow,\n        which should be provided by the LTI Tool.', max_length=255, verbose_name='LTI 1.3 OIDC URL'),
        ),
        migrations.AddField(
            model_name='externallticonfiguration',
            name='lti_1p3_private_key',
            field=models.TextField(blank=True, help_text="Platform's generated Private key. Keep this value secret.", validators=[lti_store.models.validate_rsa_key], verbose_name='LTI 1.3 Private Key'),
        ),
        migrations.AddField(
            model_name='externallticonfiguration',
            name='lti_1p3_private_key_id',
            field=models.CharField(blank=True, help_text="Platform's generated Private key ID", max_length=255, verbose_name='LTI 1.3 Private Key ID'),
        ),
        migrations.AddField(
            model_name='externallticonfiguration',
            name='lti_1p3_public_jwk',
            field=models.JSONField(blank=True, default=dict, editable=False, help_text="Platform's generated JWK keyset.", verbose_name='LTI 1.3 Public JWK'),
        ),
        migrations.AddField(
            model_name='externallticonfiguration',
            name='lti_1p3_redirect_uris',
            field=models.TextField(blank=True, default=list, help_text="Valid urls the Tool may request us to redirect the id token to.\n        The redirect uris are often the same as the launch url/deep linking url so if\n        this field is empty, it will use them as the default. If you need to use different\n        redirect uri's, enter them here. If you use this field you must enter all valid\n        redirect uri's the tool may request.", validators=[lti_store.models.validate_list_field], verbose_name='LTI 1.3 Redirect URIs'),
        ),
        migrations.AddField(
            model_name='externallticonfiguration',
            name='lti_1p3_tool_keyset_url',
            field=models.URLField(blank=True, help_text="This is the LTI Tool's JWK (JSON Web Key)\n        Keyset (JWKS) URL. This should be provided by the LTI\n        Tool. One of either lti_1p3_tool_public_key or\n        lti_1p3_tool_keyset_url must not be blank.", max_length=255, verbose_name='LTI 1.3 Tool Keyset URL'),
        ),
        migrations.AddField(
            model_name='externallticonfiguration',
            name='lti_1p3_tool_public_key',
            field=models.TextField(blank=True, help_text="This is the LTI Tool's public key.\n        This should be provided by the LTI Tool.\n        One of either lti_1p3_tool_public_key or\n        lti_1p3_tool_keyset_url must not be blank.", validators=[lti_store.models.validate_rsa_key], verbose_name='LTI 1.3 Tool Public Key'),
        ),
        migrations.AddField(
            model_name='externallticonfiguration',
            name='lti_advantage_ags_mode',
            field=models.CharField(choices=[('disabled', 'Disabled'), ('declarative', 'Allow tools to submit grades only (declarative)'), ('programmatic', 'Allow tools to manage and submit grade (programmatic)')], default='declarative', help_text='Enable LTI Advantage Assignment and Grade Services and select the functionality\n        enabled for LTI tools. The "declarative" mode (default) will provide a tool with a LineItem\n        created from the XBlock settings, while the "programmatic" one will allow tools to manage,\n        create and link the grades.', max_length=20, verbose_name='LTI Advantage Assignment and Grade Services Mode'),
        ),
        migrations.AddField(
            model_name='externallticonfiguration',
            name='lti_advantage_deep_linking_enabled',
            field=models.BooleanField(default=False, help_text='Enable LTI Advantage Deep Linking.', verbose_name='Enable LTI Advantage Deep Linking'),
        ),
        migrations.AddField(
            model_name='externallticonfiguration',
            name='lti_advantage_deep_linking_launch_url',
            field=models.URLField(blank=True, help_text='This is the LTI Advantage Deep Linking launch URL. If the LTI Tool\n        does not provide one, use the same value as lti_1p3_launch_url.', max_length=255, verbose_name='LTI Advantage Deep Linking launch URL'),
        ),
        migrations.AddField(
            model_name='externallticonfiguration',
            name='lti_advantage_enable_nrps',
            field=models.BooleanField(default=False, help_text='Enable LTI Advantage Names and Role Provisioning Services.', verbose_name='Enable LTI Advantage Names and Role Provisioning Services'),
        ),
        migrations.AlterField(
            model_name='externallticonfiguration',
            name='version',
            field=models.CharField(choices=[('lti_1p1', 'LTI 1.1'), ('lti_1p3', 'LTI 1.3')], default='lti_1p1', max_length=10),
        ),
    ]