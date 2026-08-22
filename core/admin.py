from django.contrib import admin

from .models import AuditRecord, PolicyConfig, SessionState, Trace, UseCaseProfile


@admin.register(UseCaseProfile)
class UseCaseProfileAdmin(admin.ModelAdmin):
    list_display = ("use_case_id", "name", "model_tier_preference", "is_active", "updated_at")
    search_fields = ("use_case_id", "name")


@admin.register(PolicyConfig)
class PolicyConfigAdmin(admin.ModelAdmin):
    list_display = ("use_case_profile", "version", "is_active", "created_at")
    list_filter = ("use_case_profile", "is_active")


@admin.register(Trace)
class TraceAdmin(admin.ModelAdmin):
    list_display = ("request_id", "session_id", "use_case", "status", "final_decision", "timestamp")
    list_filter = ("status", "final_decision", "use_case")
    search_fields = ("request_id", "session_id", "user_id")


@admin.register(SessionState)
class SessionStateAdmin(admin.ModelAdmin):
    list_display = ("session_id", "use_case", "turn_number", "session_risk_accumulator", "was_blocked")
    list_filter = ("use_case", "was_blocked")


@admin.register(AuditRecord)
class AuditRecordAdmin(admin.ModelAdmin):
    list_display = ("trace", "recommended_action", "final_action", "composite_risk_score", "timestamp")
    list_filter = ("recommended_action", "final_action")
