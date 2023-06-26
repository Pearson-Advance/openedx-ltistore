from django.conf import settings


def get_lti_api_base():
    """Returns LTI API base URL.

    This URL is used for LTI API calls. If LTI_API_BASE is set,
    this will override the default LTI_BASE_URL, if no setting is
    found the LMS_BASE_URL is returned.

    Returns:
        LTI API base URL string.

    """
    if hasattr(settings, "LTI_API_BASE"):
        return settings.LTI_API_BASE
    if hasattr(settings, "LTI_BASE"):
        return settings.LTI_BASE
    return settings.LMS_ROOT_URL
