from .authz import is_manager


def access(request):
    """Makes `is_manager` available in every template (core/templates/core/
    base.html's nav gating) without every single view having to add it to
    its own context — parallel to how django.contrib.auth's own context
    processor makes `user` available everywhere."""
    return {"is_manager": is_manager(request.user)}
