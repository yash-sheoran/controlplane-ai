from django.contrib import admin

from .models import (
    AuditRecord,
    FalsePositiveReport,
    PolicyConfig,
    ReviewerAction,
    SessionState,
    ThresholdChangeProposal,
    Trace,
    UseCaseProfile,
    UserFeedback,
)


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
    list_display = (
        "trace", "recommended_action", "final_action", "composite_risk_score",
        "human_review_status", "timestamp",
    )
    list_filter = ("recommended_action", "final_action", "human_review_status")


@admin.register(ReviewerAction)
class ReviewerActionAdmin(admin.ModelAdmin):
    list_display = ("audit_record", "reviewer_id", "decision", "decided_at")
    list_filter = ("decision",)


@admin.register(UserFeedback)
class UserFeedbackAdmin(admin.ModelAdmin):
    list_display = ("trace", "reviewed", "created_at")
    list_filter = ("reviewed",)


@admin.register(FalsePositiveReport)
class FalsePositiveReportAdmin(admin.ModelAdmin):
    list_display = ("audit_record", "dimension", "reported_by", "created_at")
    list_filter = ("dimension",)


@admin.register(ThresholdChangeProposal)
class ThresholdChangeProposalAdmin(admin.ModelAdmin):
    list_display = (
        "use_case_id", "bucket", "dimension", "current_threshold",
        "proposed_threshold", "status", "proposed_at",
    )
    list_filter = ("use_case_id", "bucket", "status")
    actions = ["approve_proposals", "reject_proposals"]

    @admin.action(description="Approve selected threshold change proposals")
    def approve_proposals(self, request, queryset):
        from django.utils import timezone
        queryset.update(status="APPROVED", reviewed_by=request.user.username, reviewed_at=timezone.now())

    @admin.action(description="Reject selected threshold change proposals")
    def reject_proposals(self, request, queryset):
        from django.utils import timezone
        queryset.update(status="REJECTED", reviewed_by=request.user.username, reviewed_at=timezone.now())
